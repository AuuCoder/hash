use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    windows_opencl_import_lib();
}

#[cfg(target_os = "windows")]
fn windows_opencl_import_lib() {
    if let Some(existing) = find_opencl_lib() {
        println!("cargo:rustc-link-search=native={}", existing.display());
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let import_dir = out_dir.join("opencl-import");
    fs::create_dir_all(&import_dir).expect("failed to create opencl import directory");

    let opencl_dll = find_opencl_dll().expect("OpenCL.dll not found in System32");
    let dumpbin = find_visual_studio_tool("dumpbin.exe").expect("dumpbin.exe not found");
    let libexe = find_visual_studio_tool("lib.exe").expect("lib.exe not found");

    let exports = collect_exports(&dumpbin, &opencl_dll).expect("failed to read OpenCL exports");
    if exports.is_empty() {
        panic!("OpenCL.dll exports list is empty");
    }

    let def_path = import_dir.join("OpenCL.def");
    let lib_path = import_dir.join("OpenCL.lib");
    write_def_file(&def_path, &exports).expect("failed to write OpenCL.def");

    let status = Command::new(&libexe)
        .arg(format!("/def:{}", def_path.display()))
        .arg("/machine:x64")
        .arg(format!("/out:{}", lib_path.display()))
        .current_dir(&import_dir)
        .status()
        .expect("failed to run lib.exe");

    if !status.success() {
        panic!("lib.exe failed to generate OpenCL.lib");
    }

    println!("cargo:rustc-link-search=native={}", import_dir.display());
}

#[cfg(target_os = "windows")]
fn find_opencl_lib() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(lib_env) = env::var("LIB") {
        for entry in env::split_paths(&lib_env) {
            candidates.push(entry.join("OpenCL.lib"));
        }
    }

    let common_paths = [
        r"C:\Program Files (x86)\OCL_SDK_Light\lib\x86_64\OpenCL.lib",
        r"C:\Program Files\OCL_SDK_Light\lib\x86_64\OpenCL.lib",
        r"C:\Program Files\AMD APP\lib\x86_64\OpenCL.lib",
        r"C:\Program Files (x86)\AMD APP\lib\x86_64\OpenCL.lib",
    ];

    candidates.extend(common_paths.into_iter().map(PathBuf::from));

    candidates
        .into_iter()
        .find(|path| path.exists())
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

#[cfg(target_os = "windows")]
fn find_opencl_dll() -> Option<PathBuf> {
    let system_root = env::var_os("SystemRoot")
        .or_else(|| env::var_os("WINDIR"))
        .map(PathBuf::from)?;
    let dll = system_root.join("System32").join("OpenCL.dll");
    dll.exists().then_some(dll)
}

#[cfg(target_os = "windows")]
fn find_visual_studio_tool(tool_name: &str) -> Option<PathBuf> {
    if let Some(path) = env::var_os("VCToolsInstallDir") {
        let candidate = PathBuf::from(path).join("bin").join("Hostx64").join("x64").join(tool_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let base = PathBuf::from(r"C:\Program Files\Microsoft Visual Studio");
    if !base.exists() {
        return None;
    }

    let mut stack = vec![base];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case(tool_name))
            {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn collect_exports(dumpbin: &Path, dll: &Path) -> Result<Vec<String>, String> {
    let output = Command::new(dumpbin)
        .arg("/exports")
        .arg(dll)
        .output()
        .map_err(|err| format!("failed to run dumpbin: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "dumpbin failed with status {:?}",
            output.status.code()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut exports = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let first = parts.next().unwrap_or_default();
        if !first.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if let Some(name) = cols.last() {
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@') {
                exports.push((*name).to_string());
            }
        }
    }
    exports.sort();
    exports.dedup();
    Ok(exports)
}

#[cfg(target_os = "windows")]
fn write_def_file(path: &Path, exports: &[String]) -> std::io::Result<()> {
    let mut body = String::from("LIBRARY OpenCL\r\nEXPORTS\r\n");
    for name in exports {
        body.push_str(name);
        body.push_str("\r\n");
    }
    fs::write(path, body)
}
