use super::*;
use ic_stable_structures::writer::Writer;

pub fn pre_upgrade() {
    let mut state_bytes = vec![];

    // Serialize the state.
    STATE
        .with_borrow(|s| ciborium::ser::into_writer(s, &mut state_bytes))
        .expect("failed to encode state");

    // Write the length of the serialized bytes to memory, followed by the bytes themselves.
    let len = state_bytes.len() as u32;
    let mut memory = get_upgrades_memory();
    let mut writer = Writer::new(&mut memory, 0);
    writer.write(&len.to_le_bytes()).unwrap();
    writer.write(&state_bytes).unwrap()
}
