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
            uint challenge[4];
            uint nonce_prefix_hi;
            uint nonce_prefix_lo;
            uint difficulty_bits;
            uint batch_size;
            uint counter_hi;
            uint counter_lo;
            uint _padding;
        };

        struct Result {
            atomic_uint found;
            uint gid;
            uint digest[8];
            uint _pad0;
            uint _pad1;
        };

        constant uint K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
            0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
            0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
            0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
            0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
            0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
        };

        inline uint rotr(uint x, uint n) {
            return (x >> n) | (x << (32u - n));
        }

        inline uint ch(uint x, uint y, uint z) {
            return (x & y) ^ (~x & z);
        }

        inline uint maj(uint x, uint y, uint z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        inline uint bsig0(uint x) {
            return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
        }

        inline uint bsig1(uint x) {
            return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
        }

        inline uint ssig0(uint x) {
            return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
        }

        inline uint ssig1(uint x) {
            return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
        }

        inline bool meets_difficulty(thread const uint h[8], uint difficulty_bits) {
            if (difficulty_bits == 0u) return true;
            uint full_words = difficulty_bits / 32u;
            uint rem_bits = difficulty_bits % 32u;

            for (uint i = 0u; i < full_words && i < 8u; ++i) {
                if (h[i] != 0u) return false;
            }
            if (rem_bits == 0u) return true;
            if (full_words >= 8u) return false;
            uint mask = 0xffffffffu << (32u - rem_bits);
            return (h[full_words] & mask) == 0u;
        }

        kernel void h98hash_search(
            constant Params& params [[buffer(0)]],
            device Result* result [[buffer(1)]],
            uint gid [[thread_position_in_grid]]
        ) {
            if (gid >= params.batch_size) return;

            uint nonce_lo = params.counter_lo + gid;
            uint carry = nonce_lo < params.counter_lo ? 1u : 0u;
            uint nonce_hi = params.counter_hi + carry;

            uint W[64];
            W[0] = params.challenge[0];
            W[1] = params.challenge[1];
            W[2] = params.challenge[2];
            W[3] = params.challenge[3];
            W[4] = params.nonce_prefix_hi;
            W[5] = params.nonce_prefix_lo;
            W[6] = nonce_hi;
            W[7] = nonce_lo;
            W[8] = 0x80000000u;
            W[9] = 0u;
            W[10] = 0u;
            W[11] = 0u;
            W[12] = 0u;
            W[13] = 0u;
            W[14] = 0u;
            W[15] = 256u;
            for (uint i = 16u; i < 64u; ++i) {
                W[i] = ssig1(W[i - 2u]) + W[i - 7u] + ssig0(W[i - 15u]) + W[i - 16u];
            }

            uint a = 0x6a09e667u;
            uint b = 0xbb67ae85u;
            uint c = 0x3c6ef372u;
            uint d = 0xa54ff53au;
            uint e = 0x510e527fu;
            uint f = 0x9b05688cu;
            uint g = 0x1f83d9abu;
            uint h = 0x5be0cd19u;

            for (uint i = 0u; i < 64u; ++i) {
                uint t1 = h + bsig1(e) + ch(e, f, g) + K[i] + W[i];
                uint t2 = bsig0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            uint out[8];
            out[0] = a + 0x6a09e667u;
            out[1] = b + 0xbb67ae85u;
            out[2] = c + 0x3c6ef372u;
            out[3] = d + 0xa54ff53au;
            out[4] = e + 0x510e527fu;
            out[5] = f + 0x9b05688cu;
            out[6] = g + 0x1f83d9abu;
            out[7] = h + 0x5be0cd19u;

            if (!meets_difficulty(out, params.difficulty_bits)) return;

            if (atomic_fetch_or_explicit(&(result->found), 1u, memory_order_relaxed) == 0u) {
                result->gid = gid;
                for (uint i = 0u; i < 8u; ++i) {
                    result->digest[i] = out[i];
                }
            }
        }
    "#;

    #[repr(C)]
    struct Params {
        challenge: [u32; 4],
        nonce_prefix_hi: u32,
        nonce_prefix_lo: u32,
        difficulty_bits: u32,
        batch_size: u32,
        counter_hi: u32,
        counter_lo: u32,
        padding: u32,
    }

    #[repr(C)]
    struct ResultData {
        found: u32,
        gid: u32,
        digest: [u32; 8],
        pad0: u32,
        pad1: u32,
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
        let mut prefix = [0u8; 8];
        rng.fill_bytes(&mut prefix);
        let mut counter_bytes = [0u8; 8];
        rng.fill_bytes(&mut counter_bytes);
        let mut counter = u64::from_be_bytes(counter_bytes);

        let params = Params {
            challenge: bytes_to_u32x4_be(&cfg.challenge),
            nonce_prefix_hi: u32::from_be_bytes(prefix[0..4].try_into().unwrap()),
            nonce_prefix_lo: u32::from_be_bytes(prefix[4..8].try_into().unwrap()),
            difficulty_bits: cfg.difficulty_bits,
            batch_size: cfg.batch_size,
            counter_hi: 0,
            counter_lo: 0,
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
                let hit_counter = counter.wrapping_add(result.gid as u64);
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

            counter = counter.wrapping_add(cfg.batch_size as u64);

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
            .get_function("h98hash_search", None)
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

    fn write_params(buffer: &Buffer, template: &Params, counter: u64) {
        let params = unsafe { &mut *buffer.contents().cast::<Params>() };
        *params = Params {
            challenge: template.challenge,
            nonce_prefix_hi: template.nonce_prefix_hi,
            nonce_prefix_lo: template.nonce_prefix_lo,
            difficulty_bits: template.difficulty_bits,
            batch_size: template.batch_size,
            counter_hi: (counter >> 32) as u32,
            counter_lo: counter as u32,
            padding: 0,
        };
    }

    fn reset_result(buffer: &Buffer) {
        let result = unsafe { &mut *buffer.contents().cast::<ResultData>() };
        *result = ResultData {
            found: 0,
            gid: 0,
            digest: [0; 8],
            pad0: 0,
            pad1: 0,
        };
    }

    fn read_result(buffer: &Buffer) -> ResultData {
        let result = unsafe { &*buffer.contents().cast::<ResultData>() };
        ResultData {
            found: result.found,
            gid: result.gid,
            digest: result.digest,
            pad0: result.pad0,
            pad1: result.pad1,
        }
    }

    fn build_nonce(prefix: [u8; 8], counter: u64) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&prefix);
        nonce[8..16].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    fn bytes_to_u32x4_be(bytes: &[u8; 16]) -> [u32; 4] {
        [
            u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
        ]
    }

    fn digest_words_to_bytes(words: [u32; 8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
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
