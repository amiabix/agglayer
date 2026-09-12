use std::{path::PathBuf, time::Instant};

use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, primitives::U256, L1WitnessCtx, PessimisticRootInput,
};
use ecdsa_proof_lib::AggchainECDSA;
use pessimistic_proof_core::{
    aggchain_data::{sp1::verify_sp1_aggchain_proof, AggchainData, AggchainProof, MultiSignature},
    generate_pessimistic_proof,
    local_state::commitment::{
        PessimisticRootCommitmentVersion, SignatureCommitmentValues, SignatureCommitmentVersion,
    },
    multi_batch_header::MultiBatchHeader,
    NetworkState, PessimisticProofOutput,
};
use pessimistic_proof_test_suite::{
    forest::Forest,
    sample_data::{ETH, USDC},
    AGGCHAIN_PROOF_ECDSA_ELF,
};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient as Sp1Client},
    Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};
use zisk_sdk::{AsmOptions, GuestProgram, ProofKind, ProverClient, ZiskStdin};

type Fixture = (NetworkState, MultiBatchHeader, SP1ProofWithPublicValues);

fn fixture() -> Fixture {
    if let Some(path) = std::env::var_os("SP1_AGGCHAIN_FIXTURE") {
        let client = Sp1Client::builder().light().build();
        let pk = client.setup(Elf::Static(AGGCHAIN_PROOF_ECDSA_ELF)).unwrap();
        let vk = pk.verifying_key();
        let fixture: Fixture = bincode::deserialize(&std::fs::read(path).unwrap()).unwrap();
        client.verify(&fixture.2, vk, None).unwrap();
        let AggchainData::MultisigAndAggchainProof { aggchain_proof, .. } =
            &fixture.1.aggchain_data
        else {
            panic!("expected an aggchain proof")
        };
        assert_eq!(aggchain_proof.aggchain_vkey, vk.hash_u32());
        return fixture;
    }

    let client = Sp1Client::builder().cpu().build();
    let pk = client.setup(Elf::Static(AGGCHAIN_PROOF_ECDSA_ELF)).unwrap();
    let vk = pk.verifying_key();

    let mut forest = Forest::new([(USDC, U256::from(100)), (ETH, U256::from(200))]);
    let initial = forest.state_b.clone();
    let certificate = forest.apply_events_with_version(
        &[
            (USDC, U256::from(50)),
            (ETH, U256::from(100)),
            (USDC, U256::from(10)),
        ],
        &[
            (USDC, U256::from(20)),
            (ETH, U256::from(50)),
            (USDC, U256::from(130)),
        ],
        SignatureCommitmentVersion::V2,
    );
    let mut signature_values = SignatureCommitmentValues::from(&certificate);
    let import_commitment = signature_values
        .commit_imported_bridge_exits
        .commitment(pessimistic_proof_core::proof::IMPORTED_BRIDGE_EXIT_COMMITMENT_VERSION);
    let commitment = pessimistic_proof_core::keccak::keccak256_combine([
        certificate.new_local_exit_root.as_ref(),
        import_commitment.as_slice(),
    ]);
    let witness = AggchainECDSA {
        signer: forest.get_signer(),
        signature: forest.sign(commitment).unwrap().0,
        commit_imported_bridge_exits: import_commitment.0,
        prev_local_exit_root: certificate.prev_local_exit_root,
        new_local_exit_root: certificate.new_local_exit_root,
        l1_info_root: *certificate.l1_info_root().unwrap().unwrap(),
        origin_network: forest.network_id,
    };
    let aggchain_params = witness.aggchain_params().into();
    signature_values.aggchain_params = Some(aggchain_params);
    let multisig_signature = forest
        .sign(signature_values.multisig_commitment().0.into())
        .unwrap()
        .0;
    let mut header = initial
        .make_multi_batch_header(
            &certificate,
            L1WitnessCtx {
                l1_info_root: certificate.l1_info_root().unwrap().unwrap_or_default(),
                prev_pessimistic_root: PessimisticRootInput::Computed(
                    PessimisticRootCommitmentVersion::V2,
                ),
                aggchain_data_ctx: CertificateAggchainDataCtx::LegacyEcdsa {
                    signer: forest.get_signer(),
                },
            },
        )
        .unwrap();
    header.aggchain_data = AggchainData::MultisigAndAggchainProof {
        multisig: MultiSignature {
            signatures: vec![Some(multisig_signature)],
            expected_signers: vec![forest.get_signer()],
            threshold: 1,
        },
        aggchain_proof: AggchainProof {
            aggchain_params,
            aggchain_vkey: vk.hash_u32(),
        },
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    eprintln!("Generating a real SP1 compressed proof (CPU correctness fixture)");
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    client.verify(&proof, vk, None).unwrap();
    assert_eq!(
        proof.public_values.as_slice(),
        bincode::serialize(&witness.public_values()).unwrap()
    );

    let fixture = (initial.into(), header, proof);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sp1-aggchain-fixture.bin");
    std::fs::write(&path, bincode::serialize(&fixture).unwrap()).unwrap();
    eprintln!("Reusable fixture: {}", path.display());
    fixture
}

fn stdin(state: &NetworkState, header: &MultiBatchHeader, proof: &[u8]) -> ZiskStdin {
    let stdin = ZiskStdin::new();
    stdin.write(state);
    stdin.write(header);
    stdin.write_slice(proof);
    stdin
}

fn guest_program() -> GuestProgram {
    let elf = std::env::var("ZISK_SP1_PP_ELF").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/elf/riscv64ima-zisk-zkvm-elf/release/pessimistic-proof-program-zisk"
        )
        .to_owned()
    });
    GuestProgram::from_uri(&elf).unwrap()
}

#[test]
#[ignore = "exports a cached SP1 fixture for ZisK profiling"]
fn exports_sp1_aggchain_profile_input() {
    assert!(std::env::var_os("SP1_AGGCHAIN_FIXTURE").is_some());
    let output_dir = PathBuf::from(std::env::var_os("ZISK_PROFILE_OUTPUT_DIR").unwrap());
    std::fs::create_dir_all(&output_dir).unwrap();
    let (state, header, proof) = fixture();
    let (expected, _) = generate_pessimistic_proof(state.clone(), &header).unwrap();
    stdin(&state, &header, &bincode::serialize(&proof.proof).unwrap())
        .save(output_dir.join("input.bin"))
        .unwrap();
    std::fs::write(
        output_dir.join("expected-publics.bin"),
        PessimisticProofOutput::bincode_codec()
            .serialize(&expected)
            .unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "generates a real SP1 proof and requires the sp1-aggchain ZisK ELF"]
fn verifies_sp1_compressed_proof_inside_zisk() {
    let (state, header, proof) = fixture();
    let AggchainData::MultisigAndAggchainProof { aggchain_proof, .. } = &header.aggchain_data
    else {
        panic!("expected an aggchain proof")
    };
    let proof_bytes = bincode::serialize(&proof.proof).unwrap();
    let public_hash: [u8; 32] = proof.public_values.hash().try_into().unwrap();
    let vk = aggchain_proof.aggchain_vkey;
    verify_sp1_aggchain_proof(&proof_bytes, &vk, &public_hash).unwrap();

    let mut wrong_vk = vk;
    wrong_vk[0] ^= 1;
    assert!(verify_sp1_aggchain_proof(&proof_bytes, &wrong_vk, &public_hash).is_err());
    let mut wrong_hash = public_hash;
    wrong_hash[0] ^= 1;
    assert!(verify_sp1_aggchain_proof(&proof_bytes, &vk, &wrong_hash).is_err());

    let mut altered = proof.proof.clone();
    let SP1Proof::Compressed(inner) = &mut altered else {
        panic!("expected a compressed proof")
    };
    inner.vk_merkle_proof.index ^= 1;
    assert!(
        verify_sp1_aggchain_proof(&bincode::serialize(&altered).unwrap(), &vk, &public_hash)
            .is_err()
    );

    let mut altered = proof.proof.clone();
    let SP1Proof::Compressed(inner) = &mut altered else {
        unreachable!()
    };
    inner.vk_merkle_proof.index += 1 << inner.vk_merkle_proof.path.len();
    assert!(verify_sp1_aggchain_proof(
        &bincode::serialize(&altered).unwrap(),
        &vk,
        &public_hash,
    )
    .is_err());

    let mut altered = proof.proof.clone();
    let SP1Proof::Compressed(inner) = &mut altered else {
        unreachable!()
    };
    inner.proof.main_commitment = Default::default();
    let altered_bytes = bincode::serialize(&altered).unwrap();
    assert_ne!(altered_bytes, proof_bytes);
    assert!(verify_sp1_aggchain_proof(&altered_bytes, &vk, &public_hash).is_err());

    let (expected, _) = generate_pessimistic_proof(state.clone(), &header).unwrap();
    let expected_bytes = PessimisticProofOutput::bincode_codec()
        .serialize(&expected)
        .unwrap();
    let program = guest_program();
    let client = ProverClient::embedded().execute_only().build().unwrap();
    client.setup(&program, false).unwrap();
    let execution = client
        .execute(&program, stdin(&state, &header, &proof_bytes), None)
        .unwrap();
    let mut actual = vec![0; expected_bytes.len()];
    execution.get_publics().read_slice(&mut actual);
    assert_eq!(actual, expected_bytes);
    eprintln!("ZisK guest steps: {}", execution.get_execution_steps());

    assert!(client
        .execute(&program, stdin(&state, &header, &altered_bytes), None)
        .is_err());
}

#[test]
#[ignore = "requires a cached fixture and explicit accelerated ELF/emulator paths"]
fn rejects_invalid_sp1_proofs_with_accelerated_zisk() {
    use std::{borrow::BorrowMut, fs, process::Command};

    use slop_algebra::{AbstractField, PrimeField32};
    use sp1_primitives::SP1Field;
    use sp1_recursion_executor::RecursionPublicValues;

    assert!(std::env::var_os("SP1_AGGCHAIN_FIXTURE").is_some());
    let emulator = std::env::var_os("ZISK_SP1_EMULATOR").expect("set the custom emulator");
    let elf = std::env::var_os("ZISK_SP1_PP_ELF").expect("set the accelerated ELF");
    let directory = PathBuf::from(
        std::env::var_os("ZISK_SP1_REJECTION_DIR").expect("set a new evidence directory"),
    );
    fs::create_dir(&directory).expect("evidence directory must not already exist");
    let (state, header, proof) = fixture();
    let proof_bytes = bincode::serialize(&proof.proof).unwrap();
    let (expected, _) = generate_pessimistic_proof(state.clone(), &header).unwrap();
    let expected = PessimisticProofOutput::bincode_codec()
        .serialize(&expected)
        .unwrap();
    fs::write(directory.join("expected-publics.bin"), &expected).unwrap();

    let run = |name: &str, header: &MultiBatchHeader, bytes: &[u8], error: Option<&str>| {
        let input = directory.join(format!("{name}.input.bin"));
        let output = directory.join(format!("{name}.publics.bin"));
        stdin(&state, header, bytes).save(&input).unwrap();
        let mut command = Command::new("timeout");
        command.args(["--kill-after=5s", "180s"]).arg(&emulator);
        command.arg("--elf").arg(&elf).arg("--inputs").arg(&input);
        command
            .arg("--output")
            .arg(&output)
            .args(["--max-steps", "100000000", "--log-metrics"]);
        if error.is_none() {
            command.args(["--stats", "--sdk", "--opcodes"]);
        }
        let result = command.output().unwrap();
        let mut log = result.stdout;
        log.extend_from_slice(&result.stderr);
        fs::write(directory.join(format!("{name}.log")), &log).unwrap();
        fs::write(
            directory.join(format!("{name}.status")),
            result.status.to_string(),
        )
        .unwrap();
        let log = String::from_utf8_lossy(&log);
        if let Some(error) = error {
            assert!(!result.status.success(), "{name} was accepted");
            assert!(
                !matches!(result.status.code(), Some(124 | 137)),
                "{name} timed out"
            );
            assert!(
                log.contains("invalid SP1 aggchain proof"),
                "{name}: unrelated failure: {log}"
            );
            assert!(log.contains(error), "{name}: wrong rejection: {log}");
            assert!(
                !output.exists(),
                "{name}: rejected guest wrote public output"
            );
        } else {
            assert!(result.status.success(), "{name}: {log}");
            assert!(
                log.contains("koala_poseidon2"),
                "missing precompile profile: {log}"
            );
            let actual = fs::read(output).unwrap();
            assert_eq!(actual.len(), 256);
            assert_eq!(&actual[..expected.len()], expected.as_slice());
            assert!(actual[expected.len()..].iter().all(|byte| *byte == 0));
        }
        eprintln!("accelerated regression: {name} passed");
    };

    run("valid", &header, &proof_bytes, None);
    for (name, value, error) in [
        ("wrong-program", None, "Verification"),
        (
            "noncanonical-program",
            Some(SP1Field::ORDER_U32),
            "ProgramKey",
        ),
    ] {
        let mut altered = header.clone();
        let AggchainData::MultisigAndAggchainProof { aggchain_proof, .. } =
            &mut altered.aggchain_data
        else {
            unreachable!()
        };
        aggchain_proof.aggchain_vkey[0] = value.unwrap_or(aggchain_proof.aggchain_vkey[0] ^ 1);
        run(name, &altered, &proof_bytes, Some(error));
    }
    for (name, error) in [
        ("wrong-public-digest", "PublicValues"),
        ("failed-inner-exit", "ExitCode"),
        ("incomplete-inner", "Verification"),
        ("wrong-recursion-root", "Verification"),
        ("wrong-inner-program", "Verification"),
    ] {
        let mut altered = proof.proof.clone();
        let SP1Proof::Compressed(inner) = &mut altered else {
            unreachable!()
        };
        let values: &mut RecursionPublicValues<SP1Field> =
            inner.proof.public_values.as_mut_slice().borrow_mut();
        match name {
            "wrong-public-digest" => values.committed_value_digest[0][0] += SP1Field::one(),
            "failed-inner-exit" => values.exit_code = SP1Field::one(),
            "incomplete-inner" => values.is_complete = SP1Field::zero(),
            "wrong-recursion-root" => values.vk_root[0] += SP1Field::one(),
            "wrong-inner-program" => values.sp1_vk_digest[0] += SP1Field::one(),
            _ => unreachable!(),
        }
        run(
            name,
            &header,
            &bincode::serialize(&altered).unwrap(),
            Some(error),
        );
    }
    let mut altered = proof.proof.clone();
    let SP1Proof::Compressed(inner) = &mut altered else {
        unreachable!()
    };
    inner.vk_merkle_proof.index += 1 << inner.vk_merkle_proof.path.len();
    run(
        "out-of-range-merkle-index",
        &header,
        &bincode::serialize(&altered).unwrap(),
        Some("MerkleIndex"),
    );
    run("empty", &header, &[], Some("Decode"));
    run(
        "truncated",
        &header,
        &proof_bytes[..proof_bytes.len() / 2],
        Some("Decode"),
    );
    let mut trailing = proof_bytes.clone();
    trailing.push(0);
    run("trailing", &header, &trailing, Some("Decode"));
    for (name, proof) in [
        ("core", SP1Proof::Core(vec![])),
        ("plonk", SP1Proof::Plonk(Default::default())),
        ("groth16", SP1Proof::Groth16(Default::default())),
    ] {
        run(
            name,
            &header,
            &bincode::serialize(&proof).unwrap(),
            Some("ProofType"),
        );
    }
}

#[test]
#[ignore = "requires the sp1-aggchain ZisK ELF, proving keys, and a supported GPU"]
fn proves_sp1_compressed_proof_inside_zisk() {
    let (state, header, proof) = fixture();
    let (expected, _) = generate_pessimistic_proof(state.clone(), &header).unwrap();
    let expected_bytes = PessimisticProofOutput::bincode_codec()
        .serialize(&expected)
        .unwrap();
    let proof_bytes = bincode::serialize(&proof.proof).unwrap();
    let program = guest_program();
    let mut builder = ProverClient::embedded()
        .assembly()
        .plonk()
        .asm_options(AsmOptions::default().unlock_mapped_memory())
        .gpu();
    if let Ok(path) = std::env::var("ZISK_PROVING_KEY") {
        builder = builder.proving_key(path);
    }
    let init_start = Instant::now();
    let client = builder.build().unwrap();
    eprintln!("zisk_client_init_ms={}", init_start.elapsed().as_millis());
    let setup_start = Instant::now();
    client.setup(&program).run_sync().unwrap();
    eprintln!(
        "zisk_program_setup_ms={}",
        setup_start.elapsed().as_millis()
    );
    let program_vk = program.vk().unwrap();
    let runs: usize = std::env::var("ZISK_PROOF_RUNS")
        .unwrap_or_else(|_| "1".to_owned())
        .parse()
        .unwrap();
    assert!(runs > 0);
    let output_dir = std::env::var_os("ZISK_PROOF_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sp1-in-zisk-proofs")
        });

    for run in 1..=runs {
        let prove_start = Instant::now();
        let result = client
            .prove(&program, stdin(&state, &header, &proof_bytes))
            .wrap(ProofKind::Plonk)
            .run_sync()
            .unwrap();
        let proving_ms = prove_start.elapsed().as_millis();
        let proof = result.get_proof();
        let verify_start = Instant::now();
        proof.with_program_vk(&program_vk).verify().unwrap();
        let verification_ms = verify_start.elapsed().as_millis();
        let mut actual = vec![0; expected_bytes.len()];
        proof.get_publics().read_slice(&mut actual);
        assert_eq!(actual, expected_bytes);

        let path = output_dir.join(format!("run-{run}.proof"));
        result.save_proof(&path).unwrap();
        eprintln!(
            "zisk_sp1_run={run} proving_ms={proving_ms} sdk_proving_ms={} verification_ms={verification_ms} guest_steps={} saved_proof_bytes={} proof_path={}",
            result.get_proving_time(),
            result.get_execution_steps(),
            std::fs::metadata(&path).unwrap().len(),
            path.display(),
        );
    }
}
