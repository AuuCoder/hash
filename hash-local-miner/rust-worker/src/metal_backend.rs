use crate::{emit, emit_progress, hex_string, CliError, Config, Event};

#[cfg(target_os = "macos")]
mod imp {
    use super::{emit, emit_progress, hex_string, CliError, Config, Event};
    use metal::{Buffer, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
    use objc::rc::autoreleasepool;
    use rand::RngCore;
    use std::mem::size_of;
    use std::time::{Duration, Instant};

    const SHADER_SOURCE: &str = r#"
        #include <metal_stdlib>
        using namespace metal;

        struct Params {
            ulong challenge[4];
            ulong nonce_prefix[2];
            ulong difficulty[4];
            ulong counter_hi;
            ulong counter_lo;
            uint batch_size;
            uint _padding;
        };

        struct Result {
            atomic_uint found;
            uint gid;
            ulong digest[4];
        };

        constant uint KECCAKF_ROTC[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        constant uint KECCAKF_PILN[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        };

        constant ulong KECCAKF_RNDC[24] = {
            0x0000000000000001UL, 0x0000000000008082UL,
            0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL,
            0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL,
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

        inline void keccakf(thread ulong st[25]) {
            thread ulong bc[5];
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

        inline bool digest_lt(thread const ulong st[25], constant Params& params) {
            ulong words[4] = {
                bswap64(st[0]),
                bswap64(st[1]),
                bswap64(st[2]),
                bswap64(st[3]),
            };

            for (uint i = 0; i < 4; ++i) {
                if (words[i] < params.difficulty[i]) {
                    return true;
                }
                if (words[i] > params.difficulty[i]) {
                    return false;
                }
            }
            return false;
        }

        kernel void hash256_search(
            constant Params& params [[buffer(0)]],
            device Result* result [[buffer(1)]],
            uint gid [[thread_position_in_grid]]
        ) {
            if (gid >= params.batch_size) {
                return;
            }

            ulong counter_lo = params.counter_lo + (ulong)gid;
            ulong carry = counter_lo < params.counter_lo ? 1UL : 0UL;
            ulong counter_hi = params.counter_hi + carry;

            thread ulong st[25];
            for (uint i = 0; i < 25; ++i) {
                st[i] = 0UL;
            }

            st[0] = params.challenge[0];
            st[1] = params.challenge[1];
            st[2] = params.challenge[2];
            st[3] = params.challenge[3];
            st[4] = params.nonce_prefix[0];
            st[5] = params.nonce_prefix[1];
            st[6] = bswap64(counter_hi);
            st[7] = bswap64(counter_lo);
            st[8] ^= 0x01UL;
            st[16] ^= 0x8000000000000000UL;

            keccakf(st);

            if (!digest_lt(st, params)) {
                return;
            }

            if (atomic_fetch_or_explicit(&(result->found), 1u, memory_order_relaxed) == 0u) {
                result->gid = gid;
                result->digest[0] = bswap64(st[0]);
                result->digest[1] = bswap64(st[1]);
                result->digest[2] = bswap64(st[2]);
                result->digest[3] = bswap64(st[3]);
            }
        }
    "#;

    #[repr(C)]
    struct Params {
        challenge: [u64; 4],
        nonce_prefix: [u64; 2],
        difficulty: [u64; 4],
        counter_hi: u64,
        counter_lo: u64,
        batch_size: u32,
        padding: u32,
    }

    #[repr(C)]
    struct ResultData {
        found: u32,
        gid: u32,
        digest: [u64; 4],
    }

    pub(crate) fn run(cfg: &Config) -> Result<(), CliError> {
        autoreleasepool(|| run_impl(cfg))
    }

    fn run_impl(cfg: &Config) -> Result<(), CliError> {
        let device = Device::system_default()
            .ok_or_else(|| CliError::Message("Metal device not available".into()))?;
        let command_queue = device.new_command_queue();
        let pipeline_state = create_pipeline_state(&device)?;
        let params_buffer = device.new_buffer(
            size_of::<Params>() as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let result_buffer = device.new_buffer(
            size_of::<ResultData>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let mut rng = rand::thread_rng();
        let mut prefix = [0u8; 16];
        rng.fill_bytes(&mut prefix);
        let mut counter_bytes = [0u8; 16];
        rng.fill_bytes(&mut counter_bytes);
        let mut counter = u128::from_be_bytes(counter_bytes);

        let params = Params {
            challenge: bytes_to_u64x4_le(&cfg.challenge),
            nonce_prefix: [
                u64::from_le_bytes(prefix[0..8].try_into().unwrap()),
                u64::from_le_bytes(prefix[8..16].try_into().unwrap()),
            ],
            difficulty: bytes_to_u64x4_be(&cfg.difficulty),
            counter_hi: 0,
            counter_lo: 0,
            batch_size: cfg.batch_size,
            padding: 0,
        };

        let started = Instant::now();
        let mut last_progress = Instant::now();
        let mut total_hashes = 0u64;

        loop {
            write_params(&params_buffer, &params, counter);
            reset_result(&result_buffer);

            dispatch_batch(
                &command_queue,
                &pipeline_state,
                &params_buffer,
                &result_buffer,
                cfg.batch_size,
            )?;

            total_hashes = total_hashes.saturating_add(cfg.batch_size as u64);
            let result = read_result(&result_buffer);
            if result.found != 0 {
                let gid = result.gid as u128;
                let hit_counter = counter.wrapping_add(gid);
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

    fn create_pipeline_state(device: &Device) -> Result<ComputePipelineState, CliError> {
        let options = CompileOptions::new();
        let library = device
            .new_library_with_source(SHADER_SOURCE, &options)
            .map_err(|err| CliError::Message(format!("Metal shader compile failed: {err}")))?;
        let kernel = library
            .get_function("hash256_search", None)
            .map_err(|err| CliError::Message(format!("Metal kernel lookup failed: {err}")))?;
        device
            .new_compute_pipeline_state_with_function(&kernel)
            .map_err(|err| CliError::Message(format!("Metal pipeline creation failed: {err}")))
    }

    fn dispatch_batch(
        command_queue: &metal::CommandQueue,
        pipeline_state: &ComputePipelineState,
        params_buffer: &Buffer,
        result_buffer: &Buffer,
        batch_size: u32,
    ) -> Result<(), CliError> {
        let command_buffer = command_queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(pipeline_state);
        encoder.set_buffer(0, Some(params_buffer), 0);
        encoder.set_buffer(1, Some(result_buffer), 0);

        let threads_per_group = pipeline_state.thread_execution_width().max(1);
        let threadgroup_size = MTLSize {
            width: threads_per_group as u64,
            height: 1,
            depth: 1,
        };
        let groups = (batch_size as u64 + threadgroup_size.width - 1) / threadgroup_size.width;
        let threadgroup_count = MTLSize {
            width: groups,
            height: 1,
            depth: 1,
        };

        encoder.dispatch_thread_groups(threadgroup_count, threadgroup_size);
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(())
    }

    fn write_params(buffer: &Buffer, template: &Params, counter: u128) {
        let params = unsafe { &mut *buffer.contents().cast::<Params>() };
        *params = Params {
            challenge: template.challenge,
            nonce_prefix: template.nonce_prefix,
            difficulty: template.difficulty,
            counter_hi: (counter >> 64) as u64,
            counter_lo: counter as u64,
            batch_size: template.batch_size,
            padding: 0,
        };
    }

    fn reset_result(buffer: &Buffer) {
        let result = unsafe { &mut *buffer.contents().cast::<ResultData>() };
        *result = ResultData {
            found: 0,
            gid: 0,
            digest: [0; 4],
        };
    }

    fn read_result(buffer: &Buffer) -> ResultData {
        let result = unsafe { &*buffer.contents().cast::<ResultData>() };
        ResultData {
            found: result.found,
            gid: result.gid,
            digest: result.digest,
        }
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

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{CliError, Config};

    pub(crate) fn run(_cfg: &Config) -> Result<(), CliError> {
        Err(CliError::Message(
            "Metal backend is only available on macOS".into(),
        ))
    }
}

pub(crate) use imp::run;
