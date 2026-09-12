use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, primitives::U256, L1WitnessCtx, PessimisticRootInput,
};
use ecdsa_proof_lib::AggchainECDSA;
use pessimistic_proof::{
    core::{
        commitment::{
            PessimisticRootCommitmentVersion, SignatureCommitmentValues, SignatureCommitmentVersion,
        },
        generate_pessimistic_proof, AggchainData, AggchainProof, MultiSignature,
    },
    keccak::keccak256_combine,
    multi_batch_header::MultiBatchHeader,
    unified_bridge::ImportedBridgeExitCommitmentVersion,
    NetworkState, PessimisticProofOutput,
};
use pessimistic_proof_test_suite::{
    forest::Forest,
    runner::Runner,
    sample_data::{ETH, USDC},
};
use zisk_sdk::{AsmOptions, GuestProgram, ProofKind, ProverClient, ZiskHints, ZiskStdin};

const ZISK_PP_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/elf/riscv64ima-zisk-zkvm-elf/release/pessimistic-proof-program-zisk"
);
const ZISK_AGGCHAIN_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../pessimistic-proof-test-suite/aggchain-proof-ecdsa-example/program-zisk/target/elf/riscv64ima-zisk-zkvm-elf/release/aggchain-proof-ecdsa-program-zisk"
);

fn u(value: u64) -> U256 {
    value.try_into().unwrap()
}

fn zisk_vkey_words(program: &GuestProgram) -> [u32; 8] {
    let limbs: [u64; 4] = program.vk().unwrap().vk.try_into().unwrap();
    let mut words = [0u32; 8];
    for (index, limb) in limbs.into_iter().enumerate() {
        let bytes = limb.to_be_bytes();
        words[index * 2] = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        words[index * 2 + 1] = u32::from_be_bytes(bytes[4..].try_into().unwrap());
    }
    words
}

fn hints_from_env(name: &str) -> Option<ZiskHints> {
    std::env::var_os(name)
        .map(ZiskHints::from_file)
        .transpose()
        .unwrap()
}

fn fixture() -> (
    NetworkState,
    MultiBatchHeader,
    PessimisticProofOutput,
    Vec<u8>,
) {
    let mut forest = Forest::new([(USDC, u(100)), (ETH, u(200))]);
    let initial_state_data = forest.state_b.clone();
    let certificate = forest.apply_events(
        &[(USDC, u(50)), (ETH, u(100)), (USDC, u(10))],
        &[(USDC, u(20)), (ETH, u(50)), (USDC, u(130))],
    );
    let l1_info_root = certificate.l1_info_root().unwrap().unwrap_or_default();
    let batch_header = initial_state_data
        .make_multi_batch_header(
            &certificate,
            L1WitnessCtx {
                l1_info_root,
                prev_pessimistic_root: PessimisticRootInput::Computed(
                    PessimisticRootCommitmentVersion::V2,
                ),
                aggchain_data_ctx: CertificateAggchainDataCtx::LegacyEcdsa {
                    signer: forest.get_signer(),
                },
            },
        )
        .unwrap();
    let initial_state: NetworkState = initial_state_data.into();
    let (native_output, _) =
        generate_pessimistic_proof(initial_state.clone(), &batch_header).unwrap();
    let expected_bytes = PessimisticProofOutput::bincode_codec()
        .serialize(&native_output)
        .unwrap();

    (initial_state, batch_header, native_output, expected_bytes)
}

#[test]
fn native_sp1_and_zisk_outputs_are_identical() {
    let (initial_state, batch_header, native_output, expected_bytes) = fixture();
    let (sp1_output, _) = Runner::default()
        .execute(&initial_state, &batch_header)
        .unwrap();
    assert_eq!(sp1_output, native_output);

    let program = GuestProgram::from_uri(ZISK_PP_ELF).unwrap();
    let client = ProverClient::embedded().execute_only().build().unwrap();
    client.setup(&program, false).unwrap();
    let stdin = ZiskStdin::new();
    stdin.write(&initial_state);
    stdin.write(&batch_header);
    let execution = client.execute(&program, stdin, None).unwrap();
    let mut zisk_bytes = vec![0u8; expected_bytes.len()];
    execution.get_publics().read_slice(&mut zisk_bytes);
    assert_eq!(zisk_bytes, expected_bytes);
}

#[test]
#[ignore = "requires a configured ZisK prover"]
fn generate_and_verify_zisk_proof() {
    let (initial_state, batch_header, _, expected_bytes) = fixture();
    let program = GuestProgram::from_uri(ZISK_PP_ELF).unwrap();
    let mut builder = ProverClient::embedded().assembly().gpu();
    if let Ok(proving_key) = std::env::var("ZISK_PROVING_KEY") {
        builder = builder.proving_key(proving_key);
    }
    let client = builder.build().unwrap();
    let hints = hints_from_env("ZISK_PP_HINTS");
    let setup = client.setup(&program);
    if hints.is_some() {
        setup.with_hints().run_sync().unwrap();
    } else {
        setup.run_sync().unwrap();
    }

    let stdin = ZiskStdin::new();
    stdin.write(&initial_state);
    stdin.write(&batch_header);
    let prove = client.prove(&program, stdin);
    let prove = if let Some(hints) = hints {
        prove.hints(hints)
    } else {
        prove
    };
    let result = prove
        .wrap(ProofKind::VadcopFinalMinimal)
        .run_sync()
        .unwrap();
    let proof = result.get_proof();
    proof
        .with_program_vk(&program.vk().unwrap())
        .verify()
        .unwrap();

    let mut zisk_bytes = vec![0u8; expected_bytes.len()];
    proof.get_publics().read_slice(&mut zisk_bytes);
    assert_eq!(zisk_bytes, expected_bytes);
}

#[test]
#[ignore = "requires a configured ZisK prover"]
fn generate_and_verify_recursive_zisk_proof() {
    let mut forest = Forest::new([(USDC, u(100)), (ETH, u(200))]);
    let initial_state_data = forest.state_b.clone();
    let certificate = forest.apply_events_with_version(
        &[(USDC, u(50)), (ETH, u(100)), (USDC, u(10))],
        &[(USDC, u(20)), (ETH, u(50)), (USDC, u(130))],
        SignatureCommitmentVersion::V2,
    );
    let agglayer_types::aggchain_proof::AggchainData::ECDSA { .. } = certificate.aggchain_data
    else {
        panic!("inconsistent fixture")
    };
    let certificate_signature_values = SignatureCommitmentValues::from(&certificate);
    let imported_bridge_exit_commitment = certificate_signature_values
        .commit_imported_bridge_exits
        .commitment(ImportedBridgeExitCommitmentVersion::V3);
    let aggchain_commitment = keccak256_combine([
        certificate.new_local_exit_root.as_ref(),
        imported_bridge_exit_commitment.as_slice(),
    ]);
    let (aggchain_signature, _) = forest.sign(aggchain_commitment).unwrap();
    let aggchain_witness = AggchainECDSA {
        signer: certificate
            .retrieve_signer(SignatureCommitmentVersion::V2)
            .unwrap(),
        signature: aggchain_signature,
        commit_imported_bridge_exits: imported_bridge_exit_commitment.0,
        prev_local_exit_root: certificate.prev_local_exit_root,
        new_local_exit_root: certificate.new_local_exit_root,
        l1_info_root: *certificate.l1_info_root().unwrap().unwrap(),
        origin_network: forest.network_id,
    };

    let aggchain_program = GuestProgram::from_uri(ZISK_AGGCHAIN_ELF).unwrap();
    let pp_program = GuestProgram::from_uri(ZISK_PP_ELF).unwrap();
    let mut builder = ProverClient::embedded()
        .assembly()
        .plonk()
        .asm_options(AsmOptions::default().unlock_mapped_memory())
        .gpu();
    if let Ok(proving_key) = std::env::var("ZISK_PROVING_KEY") {
        builder = builder.proving_key(proving_key);
    }
    let client = builder.build().unwrap();
    let aggchain_hints = hints_from_env("ZISK_AGGCHAIN_HINTS");
    let setup = client.setup(&aggchain_program);
    if aggchain_hints.is_some() {
        setup.with_hints().run_sync().unwrap();
    } else {
        setup.run_sync().unwrap();
    }

    let aggchain_params = aggchain_witness.aggchain_params().into();
    let mut signature_values = SignatureCommitmentValues::from(&certificate);
    signature_values.aggchain_params = Some(aggchain_params);
    let (multisig_signature, _) = forest
        .sign(signature_values.multisig_commitment().0.into())
        .unwrap();

    let mut batch_header = initial_state_data
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
    batch_header.aggchain_data = AggchainData::MultisigAndAggchainProof {
        multisig: MultiSignature {
            signatures: vec![Some(multisig_signature)],
            expected_signers: vec![forest.get_signer()],
            threshold: 1,
        },
        aggchain_proof: AggchainProof {
            aggchain_params,
            aggchain_vkey: zisk_vkey_words(&aggchain_program),
        },
    };

    let initial_state: NetworkState = initial_state_data.into();
    let (expected_output, _) =
        generate_pessimistic_proof(initial_state.clone(), &batch_header).unwrap();
    let expected_bytes = PessimisticProofOutput::bincode_codec()
        .serialize(&expected_output)
        .unwrap();

    let aggchain_stdin = ZiskStdin::new();
    aggchain_stdin.write(&aggchain_witness);
    let prove = client.prove(&aggchain_program, aggchain_stdin);
    let prove = if let Some(hints) = aggchain_hints {
        prove.hints(hints)
    } else {
        prove
    };
    let aggchain_result = prove
        .wrap(ProofKind::VadcopFinalMinimal)
        .run_sync()
        .unwrap();
    let aggchain_proof_bytes = aggchain_result.get_proof_bytes().unwrap();
    drop(aggchain_result);

    let pp_stdin = ZiskStdin::new();
    pp_stdin.write(&initial_state);
    pp_stdin.write(&batch_header);
    pp_stdin.write_slice(&aggchain_proof_bytes);

    let pp_hints = hints_from_env("ZISK_PP_HINTS");
    let setup = client.setup(&pp_program);
    if pp_hints.is_some() {
        setup.with_hints().run_sync().unwrap();
    } else {
        setup.run_sync().unwrap();
    }
    let prove = client.prove(&pp_program, pp_stdin);
    let prove = if let Some(hints) = pp_hints {
        prove.hints(hints)
    } else {
        prove
    };
    let pp_result = prove.wrap(ProofKind::Plonk).run_sync().unwrap();
    let proof = pp_result.get_proof();
    proof
        .with_program_vk(&pp_program.vk().unwrap())
        .verify()
        .unwrap();

    let mut actual_bytes = vec![0u8; expected_bytes.len()];
    proof.get_publics().read_slice(&mut actual_bytes);
    assert_eq!(actual_bytes, expected_bytes);
}
