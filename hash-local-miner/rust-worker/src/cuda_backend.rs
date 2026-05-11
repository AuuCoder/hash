#[cfg(not(target_os = "macos"))]
mod imp {
    use crate::{emit, emit_progress, hex_string, CliError, Config, Event};
    use cudarc::driver::{CudaContext, DeviceRepr, DriverError, LaunchConfig, PushKernelArg, ValidAsZeroBits};
    use cudarc::nvrtc::{compile_ptx, CompileError};
    use rand::RngCore;
    use std::time::{Duration, Instant};

    const KERNEL_SOURCE: &str = r#"
        typedef unsigned int uint;
        typedef unsigned long long ulonglong;

        struct Params {
            ulonglong challenge[4];
            ulonglong nonce_prefix[2];
            ulonglong difficulty[4];
            ulonglong counter_hi;
            ulonglong counter_lo;
            uint batch_size;
            uint _padding;
        };

        struct ResultData {
            int found;
            uint gid;
            ulonglong digest[4];
        };

        __device__ __forceinline__ ulonglong rotl64(ulonglong x, uint shift) {
            return (x << shift) | (x >> (64 - shift));
        }

        __device__ __forceinline__ ulonglong bswap64(ulonglong x) {
            return ((x & 0x00000000000000ffULL) << 56) |
                   ((x & 0x000000000000ff00ULL) << 40) |
                   ((x & 0x0000000000ff0000ULL) << 24) |
                   ((x & 0x00000000ff000000ULL) << 8)  |
                   ((x & 0x000000ff00000000ULL) >> 8)  |
                   ((x & 0x0000ff0000000000ULL) >> 24) |
                   ((x & 0x00ff000000000000ULL) >> 40) |
                   ((x & 0xff00000000000000ULL) >> 56);
        }

        __device__ __forceinline__ void keccakf(ulonglong st[25]) {
            const uint KECCAKF_ROTC[24] = {
                1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
            };
            const uint KECCAKF_PILN[24] = {
                10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
            };
            const ulonglong KECCAKF_RNDC[24] = {
                0x0000000000000001ULL, 0x0000000000008082ULL,
                0x800000000000808aULL, 0x8000000080008000ULL,
                0x000000000000808bULL, 0x0000000080000001ULL,
                0x8000000080008081ULL, 0x8000000000008009ULL,
                0x000000000000008aULL, 0x0000000000000088ULL,
                0x0000000080008009ULL, 0x000000008000000aULL,
                0x800000008000808bULL, 0x800000000000008bULL,
                0x8000000000008089ULL, 0x8000000000008003ULL,
                0x8000000000008002ULL, 0x8000000000000080ULL,
                0x000000000000800aULL, 0x800000008000000aULL,
                0x8000000080008081ULL, 0x8000000000008080ULL,
                0x0000000080000001ULL, 0x8000000080008008ULL
            };

            ulonglong bc[5];
            ulonglong t;

            #pragma unroll
            for (uint round = 0; round < 24; ++round) {
                #pragma unroll
                for (uint i = 0; i < 5; ++i) {
                    bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
                }

                #pragma unroll
                for (uint i = 0; i < 5; ++i) {
                    t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                    st[i] ^= t;
                    st[i + 5] ^= t;
                    st[i + 10] ^= t;
                    st[i + 15] ^= t;
                    st[i + 20] ^= t;
                }

                t = st[1];
                #pragma unroll
                for (uint i = 0; i < 24; ++i) {
                    uint j = KECCAKF_PILN[i];
                    bc[0] = st[j];
                    st[j] = rotl64(t, KECCAKF_ROTC[i]);
                    t = bc[0];
                }

                #pragma unroll
                for (uint row = 0; row < 25; row += 5) {
                    #pragma unroll
                    for (uint i = 0; i < 5; ++i) {
                        bc[i] = st[row + i];
                    }
                    #pragma unroll
                    for (uint i = 0; i < 5; ++i) {
                        st[row + i] = bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
                    }
                }

                st[0] ^= KECCAKF_RNDC[round];
            }
        }

        __device__ __forceinline__ int digest_lt(const ulonglong st[25], const Params& params) {
            const ulonglong words[4] = {
                bswap64(st[0]),
                bswap64(st[1]),
                bswap64(st[2]),
                bswap64(st[3]),
            };

            #pragma unroll
            for (uint i = 0; i < 4; ++i) {
                if (words[i] < params.difficulty[i]) {
                    return 1;
                }
                if (words[i] > params.difficulty[i]) {
                    return 0;
                }
            }
            return 0;
        }

        extern "C" __global__ void hash256_search(Params params, ResultData* result) {
            uint gid = (blockIdx.x * blockDim.x) + threadIdx.x;
            if (gid >= params.batch_size) {
                return;
            }

            ulonglong counter_lo = params.counter_lo + (ulonglong)gid;
            ulonglong carry = counter_lo < params.counter_lo ? 1ULL : 0ULL;
            ulonglong counter_hi = params.counter_hi + carry;

            ulonglong st[25];
            #pragma unroll
            for (uint i = 0; i < 25; ++i) {
                st[i] = 0ULL;
            }

            st[0] = params.challenge[0];
            st[1] = params.challenge[1];
            st[2] = params.challenge[2];
            st[3] = params.challenge[3];
            st[4] = params.nonce_prefix[0];
            st[5] = params.nonce_prefix[1];
            st[6] = bswap64(counter_hi);
            st[7] = bswap64(counter_lo);
            st[8] = 0x01ULL;
            st[16] = 0x8000000000000000ULL;

            keccakf(st);

            if (!digest_lt(st, params)) {
                return;
            }

            if (atomicCAS(&result->found, 0, 1) == 0) {
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

    unsafe impl DeviceRepr for Params {}
    unsafe impl ValidAsZeroBits for Params {}

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct ResultData {
        found: i32,
        gid: u32,
        digest: [u64; 4],
    }

    unsafe impl DeviceRepr for ResultData {}
    unsafe impl ValidAsZeroBits for ResultData {}

    pub(crate) fn run(cfg: &Config) -> Result<(), CliError> {
        let ptx = compile_ptx(KERNEL_SOURCE).map_err(nvrtc_error)?;
        let ctx = CudaContext::new(cfg.cuda_device).map_err(cuda_error)?;
        let stream = ctx.default_stream();
        let module = ctx.load_module(ptx).map_err(cuda_error)?;
        let function = module.load_function("hash256_search").map_err(cuda_error)?;

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

        let block_size = cfg.cuda_block_size;
        let grid_dim = cfg.batch_size.div_ceil(block_size);
        let launch_cfg = LaunchConfig {
            grid_dim: (grid_dim, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        let started = Instant::now();
        let mut last_progress = Instant::now();
        let mut total_hashes = 0u64;
        let mut result_dev = stream.alloc_zeros::<ResultData>(1).map_err(cuda_error)?;
        let result_reset = [ResultData::default()];
        let mut result_host = [ResultData::default()];

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

            stream
                .memcpy_htod(&result_reset[..], &mut result_dev)
                .map_err(cuda_error)?;

            unsafe {
                stream
                    .launch_builder(&function)
                    .arg(&params)
                    .arg(&mut result_dev)
                    .launch(launch_cfg)
                    .map_err(cuda_error)?;
            }

            stream
                .memcpy_dtoh(&result_dev, &mut result_host[..])
                .map_err(cuda_error)?;

            total_hashes = total_hashes.saturating_add(cfg.batch_size as u64);
            let result = result_host[0];

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

    fn cuda_error(err: DriverError) -> CliError {
        CliError::Message(format!(
            "CUDA worker failed: {err}. 请确认 NVIDIA 驱动可用，并且系统里有支持 NVRTC 的 CUDA 运行时/Toolkit。"
        ))
    }

    fn nvrtc_error(err: CompileError) -> CliError {
        CliError::Message(format!(
            "CUDA kernel compile failed: {err}. 请确认系统里有支持 NVRTC 的 CUDA Toolkit。"
        ))
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
            "CUDA backend is not available on macOS in this project.".into(),
        ))
    }
}

pub(crate) use imp::run;
