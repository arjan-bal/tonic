use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Dependency {
    pub crate_name: String,
    pub proto_import_paths: Vec<PathBuf>,
    pub proto_files: Vec<String>,
}

impl Into<protobuf_codegen::Dependency> for &Dependency {
    fn into(self) -> protobuf_codegen::Dependency {
        protobuf_codegen::Dependency {
            crate_name: self.crate_name.clone(),
            proto_import_paths: self.proto_import_paths.clone(),
            // TODO: Is this useful to expose the following field? It's not used
            // by protobuf codegen.
            c_include_paths: Vec::new(),
            proto_files: self.proto_files.clone(),
        }
    }
}

/// Service generator builder.
#[derive(Debug, Clone)]
pub struct CodeGen {
    inputs: Vec<PathBuf>,
    output_dir: PathBuf,
    includes: Vec<PathBuf>,
    dependencies: Vec<Dependency>,
}

impl CodeGen {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            output_dir: PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("grpc_generated"),
            includes: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    pub fn input(&mut self, input: impl AsRef<Path>) -> &mut Self {
        self.inputs.push(input.as_ref().to_owned());
        self
    }

    pub fn inputs(&mut self, inputs: impl IntoIterator<Item = impl AsRef<Path>>) -> &mut Self {
        self.inputs
            .extend(inputs.into_iter().map(|input| input.as_ref().to_owned()));
        self
    }

    pub fn output_dir(&mut self, output_dir: impl AsRef<Path>) -> &mut Self {
        self.output_dir = output_dir.as_ref().to_owned();
        self
    }

    pub fn include(&mut self, include: impl AsRef<Path>) -> &mut Self {
        self.includes.push(include.as_ref().to_owned());
        self
    }

    pub fn includes(&mut self, includes: impl Iterator<Item = impl AsRef<Path>>) -> &mut Self {
        self.includes.extend(
            includes
                .into_iter()
                .map(|include| include.as_ref().to_owned()),
        );
        self
    }

    pub fn dependency(&mut self, deps: Vec<Dependency>) -> &mut Self {
        self.dependencies.extend(deps);
        self
    }

    pub fn generate_and_compile(&self) -> Result<(), String> {
        // Generate the message code.
        protobuf_codegen::CodeGen::new()
            .inputs(self.inputs.clone())
            .output_dir(self.output_dir.clone())
            .includes(self.includes.iter())
            .dependency(self.dependencies.iter().map(|d| d.into()).collect())
            .generate_and_compile()
            .unwrap();

        // Generate the service code.
        let mut cmd = std::process::Command::new("protoc");
        for input in &self.inputs {
            cmd.arg(input);
        }
        if !self.output_dir.exists() {
            // Attempt to make the directory if it doesn't exist
            let _ = std::fs::create_dir(&self.output_dir);
        }

        // The protobuf message code build already calls
        // "cargo:rerun-if-changed", we don't need to do it here.

        cmd.arg(format!("--rust-grpc_out={}", self.output_dir.display()))
            .arg("--rust-grpc_opt=experimental-codegen=enabled");
        for include in &self.includes {
            cmd.arg(format!("--proto_path={}", include.display()));
        }
        for dep in &self.dependencies {
            for path in &dep.proto_import_paths {
                cmd.arg(format!("--proto_path={}", path.display()));
            }
        }

        // The crate mapping file is created by the protobuf message codegen.
        let crate_mapping_path = self.output_dir.join("crate_mapping.txt");
        cmd.arg(format!(
            "--rust_opt=crate_mapping={}",
            crate_mapping_path.display()
        ));
        let output = cmd
            .output()
            .map_err(|e| format!("failed to run protoc: {}", e))?;
        println!("{}", std::str::from_utf8(&output.stdout).unwrap());
        eprintln!("{}", std::str::from_utf8(&output.stderr).unwrap());
        assert!(output.status.success());
        Ok(())
    }
}
