#[cfg(not(target_os = "macos"))]
mod imp {
    use crate::{emit, emit_progress, hex_string, CliError, Config, Event};
    use ocl::{flags, Buffer, Device, Platform, ProQue};
    use rand::RngCore;
    use std::time::{Duration, Instant};

    const KERNEL_SOURCE: &str = r#"
        typedef struct {
            ulong challenge[4];
            ulong nonce_prefix[2];
            ulong difficulty[4];
            ulong counter_hi;
            ulong counter_lo;
            uint batch_size;
            uint _padding;
        } Params;

        typedef struct {
            int found;
            uint gid;
            ulong digest[4];
        } ResultData;

        __constant uint KECCAKF_ROTC[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        __constant uint KECCAKF_PILN[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        };

        __constant ulong KECCAKF_RNDC[24] = {
            0x0000000000000001UL, 0x0000000000008082UL,
            0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL,
            0x0000000080008009UL, 0x000000008000000aUL,
            0x800000008000808bUL, 0x800000000000008bUL,
            0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL,
            0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL,
            0x0000000080000001UL, 0x8000000080008008UL
        };

        inline ulong rotl64(ulong x, uint shift) {
            return (x << shift) | (x >> (64 - shift));
        }

        inline ulong bswap64(ulong x) {
            return ((x & 0x00000000000000ffUL) << 56) |
                   ((x & 0x000000000000ff00UL) << 40) |
                   ((x & 0x0000000000ff0000UL) << 24) |
                   ((x & 0x00000000ff000000UL) << 8)  |
                   ((x & 0x000000ff00000000UL) >> 8)  |
                   ((x & 0x0000ff0000000000UL) >> 24) |
                   ((x & 0x00ff000000000000UL) >> 40) |
                   ((x & 0xff00000000000000UL) >> 56);
        }

        inline void keccakf(ulong st[25]) {
            ulong bc[5];
            ulong t;

            for (uint round = 0; round < 24; ++round) {
                for (uint i = 0; i < 5; ++i) {
                    bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
                }

                for (uint i = 0; i < 5; ++i) {
                    t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                    st[i] ^= t;
                    st[i + 5] ^= t;
                    st[i + 10] ^= t;
                    st[i + 15] ^= t;
                    st[i + 20] ^= t;
                }

                t = st[1];
                for (uint i = 0; i < 24; ++i) {
                    uint j = KECCAKF_PILN[i];
                    bc[0] = st[j];
                    st[j] = rotl64(t, KECCAKF_ROTC[i]);
                    t = bc[0];
                }

                for (uint row = 0; row < 25; row += 5) {
                    for (uint i = 0; i < 5; ++i) {
                        bc[i] = st[row + i];
                    }
                    for (uint i = 0; i < 5; ++i) {
                        st[row + i] = bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
                    }
                }

                st[0] ^= KECCAKF_RNDC[round];
            }
        }

        inline int digest_lt(ulong st[25], __global const Params* params) {
            ulong words[4] = {
                bswap64(st[0]),
                bswap64(st[1]),
                bswap64(st[2]),
                bswap64(st[3]),
            };

            for (uint i = 0; i < 4; ++i) {
                if (words[i] < params->difficulty[i]) {
                    return 1;
                }
                if (words[i] > params->difficulty[i]) {
                    return 0;
                }
            }
            return 0;
        }

        __kernel void hash256_search(__global const Params* params, __global ResultData* result) {
            uint gid = get_global_id(0);
            if (gid >= params->batch_size) {
                return;
            }

            ulong counter_lo = params->counter_lo + (ulong)gid;
            ulong carry = counter_lo < params->counter_lo ? 1UL : 0UL;
            ulong counter_hi = params->counter_hi + carry;

            ulong st[25];
            for (uint i = 0; i < 25; ++i) {
                st[i] = 0UL;
            }

            st[0] = params->challenge[0];
            st[1] = params->challenge[1];
            st[2] = params->challenge[2];
            st[3] = params->challenge[3];
            st[4] = params->nonce_prefix[0];
            st[5] = params->nonce_prefix[1];
            st[6] = bswap64(counter_hi);
            st[7] = bswap64(counter_lo);
            st[8] = 0x01UL;
            st[16] = 0x8000000000000000UL;

            keccakf(st);

            if (!digest_lt(st, params)) {
                return;
            }

            if (atomic_cmpxchg((volatile __global int*)&result->found, 0, 1) == 0) {
                result->gid = gid;
                result->digest[0] = bswap64(st[0]);
                result->digest[1] = bswap64(st[1]);
                result->digest[2] = bswap64(st[2]);
                result->digest[3] = bswap64(st[3]);
            }
        }
    "#;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct Params {
        challenge: [u64; 4],
        nonce_prefix: [u64; 2],
        difficulty: [u64; 4],
        counter_hi: u64,
        counter_lo: u64,
        batch_size: u32,
        padding: u32,
    }

    unsafe impl ocl::OclPrm for Params {}

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct ResultData {
        found: i32,
        gid: u32,
        digest: [u64; 4],
    }

    unsafe impl ocl::OclPrm for ResultData {}

    pub(crate) fn run(cfg: &Config) -> Result<(), CliError> {
        let (platform, device) = select_device()?;
        let work_group_size = resolve_work_group_size(&device, cfg.work_group_size)?;
        let global_work_size = round_up_to_multiple(cfg.batch_size as usize, work_group_size);
        let pro_que = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(KERNEL_SOURCE)
            .dims(global_work_size)
            .build()
            .map_err(ocl_error)?;

        let params_buffer = Buffer::<Params>::builder()
            .queue(pro_que.queue().clone())
            .flags(flags::MEM_READ_ONLY)
            .len(1)
            .build()
            .map_err(ocl_error)?;
        let result_buffer = Buffer::<ResultData>::builder()
            .queue(pro_que.queue().clone())
            .flags(flags::MEM_READ_WRITE)
            .len(1)
            .build()
            .map_err(ocl_error)?;
        let kernel = pro_que
            .kernel_builder("hash256_search")
            .arg(&params_buffer)
            .arg(&result_buffer)
            .build()
            .map_err(ocl_error)?;

        let mut rng = rand::thread_rng();
        let mut prefix = [0u8; 16];
        rng.fill_bytes(&mut prefix);
        let mut counter_bytes = [0u8; 16];
        rng.fill_bytes(&mut counter_bytes);
        let mut counter = u128::from_be_bytes(counter_bytes);

        let challenge = bytes_to_u64x4_le(&cfg.challenge);
        let difficulty = bytes_to_u64x4_be(&cfg.difficulty);
        let nonce_prefix = [
            u64::from_le_bytes(prefix[0..8].try_into().unwrap()),
            u64::from_le_bytes(prefix[8..16].try_into().unwrap()),
        ];

        let started = Instant::now();
        let mut last_progress = Instant::now();
        let mut total_hashes = 0u64;

        loop {
            let params = Params {
                challenge,
                nonce_prefix,
                difficulty,
                counter_hi: (counter >> 64) as u64,
                counter_lo: counter as u64,
                batch_size: cfg.batch_size,
                padding: 0,
            };
            let params_src = [params];
            params_buffer
                .write(&params_src[..])
                .enq()
                .map_err(ocl_error)?;
            let result_reset = [ResultData::default()];
            result_buffer
                .write(&result_reset[..])
                .enq()
                .map_err(ocl_error)?;

            unsafe {
                kernel
                    .cmd()
                    .global_work_size(global_work_size)
                    .local_work_size(work_group_size)
                    .enq()
                    .map_err(ocl_error)?;
            }
            pro_que.queue().finish().map_err(ocl_error)?;

            total_hashes = total_hashes.saturating_add(cfg.batch_size as u64);
            let mut results = [ResultData::default()];
            result_buffer
                .read(&mut results[..])
                .enq()
                .map_err(ocl_error)?;
            let result = results[0];

            if result.found != 0 {
                let hit_counter = counter.wrapping_add(result.gid as u128);
                let nonce = build_nonce(prefix, hit_counter);
                let digest = digest_words_to_bytes(result.digest);
                emit(&Event::Hit {
                    nonce_hex: hex_string(&nonce),
                    digest_hex: hex_string(&digest),
                    hashes: total_hashes,
                    elapsed_ms: started.elapsed().as_millis(),
                });
                emit(&Event::Stopped {
                    hashes: total_hashes,
                    elapsed_ms: started.elapsed().as_millis(),
                });
                return Ok(());
            }

            counter = counter.wrapping_add(cfg.batch_size as u128);

            if last_progress.elapsed() >= Duration::from_millis(cfg.progress_ms) {
                emit_progress(total_hashes, started.elapsed());
                last_progress = Instant::now();
            }
        }
    }

    fn select_device() -> Result<(Platform, Device), CliError> {
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err(CliError::Message(
                "OpenCL platform not found. Windows + AMD 请先安装带 OpenCL 运行时的 AMD Adrenalin 驱动。".into(),
            ));
        }

        let mut first_gpu: Option<(Platform, Device)> = None;
        let mut first_device: Option<(Platform, Device)> = None;

        for platform in platforms {
            for device in Device::list(platform, Some(flags::DEVICE_TYPE_GPU)).unwrap_or_default() {
                let vendor = device.vendor().unwrap_or_default().to_ascii_lowercase();
                let name = device.name().unwrap_or_default().to_ascii_lowercase();
                if vendor.contains("amd")
                    || vendor.contains("advanced micro devices")
                    || name.contains("radeon")
                {
                    return Ok((platform, device));
                }
                if first_gpu.is_none() {
                    first_gpu = Some((platform, device));
                }
            }

            if first_device.is_none() {
                if let Some(device) = Device::list_all(platform).unwrap_or_default().into_iter().next() {
                    first_device = Some((platform, device));
                }
            }
        }

        first_gpu.or(first_device).ok_or_else(|| {
            CliError::Message(
                "没有找到可用的 OpenCL 设备。请确认 AMD 显卡驱动已安装，并且系统里能看到 OpenCL GPU。".into(),
            )
        })
    }

    fn ocl_error(err: ocl::Error) -> CliError {
        CliError::Message(format!("OpenCL worker failed: {err}"))
    }

    fn resolve_work_group_size(
        device: &Device,
        requested: Option<usize>,
    ) -> Result<usize, CliError> {
        let max_work_group_size = device.max_wg_size().map_err(ocl_error)?;
        if max_work_group_size == 0 {
            return Err(CliError::Message(
                "OpenCL device reported max work-group size = 0".into(),
            ));
        }

        if let Some(value) = requested {
            if value > max_work_group_size {
                return Err(CliError::Message(format!(
                    "OpenCL work-group size {value} exceeds device max {max_work_group_size}"
                )));
            }
            return Ok(value);
        }

        for candidate in [256usize, 128, 64, 32, 16, 8, 4, 2, 1] {
            if candidate <= max_work_group_size {
                return Ok(candidate);
            }
        }

        Ok(1)
    }

    fn round_up_to_multiple(value: usize, multiple: usize) -> usize {
        if multiple <= 1 {
            return value;
        }
        value.div_ceil(multiple) * multiple
    }

    fn build_nonce(prefix: [u8; 16], counter: u128) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        nonce[..16].copy_from_slice(&prefix);
        nonce[16..32].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    fn bytes_to_u64x4_le(bytes: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]
    }

    fn bytes_to_u64x4_be(bytes: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        ]
    }

    fn digest_words_to_bytes(words: [u64; 4]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[0..8].copy_from_slice(&words[0].to_be_bytes());
        digest[8..16].copy_from_slice(&words[1].to_be_bytes());
        digest[16..24].copy_from_slice(&words[2].to_be_bytes());
        digest[24..32].copy_from_slice(&words[3].to_be_bytes());
        digest
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use crate::{CliError, Config};

    pub(crate) fn run(_cfg: &Config) -> Result<(), CliError> {
        Err(CliError::Message(
            "OpenCL backend is not enabled on macOS in this project; use --backend metal instead.".into(),
        ))
    }
}

pub(crate) use imp::run;
