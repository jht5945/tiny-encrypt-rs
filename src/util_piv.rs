use rust_util::{simple_error, XResult};
use yubikey::piv::{RetiredSlotId, SlotId};

pub fn get_slot_id(slot: &str) -> XResult<SlotId> {
    let slot_lower = slot.to_lowercase();
    Ok(match slot_lower.as_str() {
        "9a" | "auth" | "authentication" => SlotId::Authentication,
        "9c" | "sign" | "signature" => SlotId::Signature,
        "9d" | "keym" | "keymanagement" => SlotId::KeyManagement,
        "9e" | "card" | "cardauthentication" => SlotId::CardAuthentication,
        "r1" | "82" => SlotId::Retired(RetiredSlotId::R1),
        "r2" | "83" => SlotId::Retired(RetiredSlotId::R2),
        "r3" | "84" => SlotId::Retired(RetiredSlotId::R3),
        "r4" | "85" => SlotId::Retired(RetiredSlotId::R4),
        "r5" | "86" => SlotId::Retired(RetiredSlotId::R5),
        "r6" | "87" => SlotId::Retired(RetiredSlotId::R6),
        "r7" | "88" => SlotId::Retired(RetiredSlotId::R7),
        "r8" | "89" => SlotId::Retired(RetiredSlotId::R8),
        "r9" | "8a" => SlotId::Retired(RetiredSlotId::R9),
        "r10" | "8b" => SlotId::Retired(RetiredSlotId::R10),
        "r11" | "8c" => SlotId::Retired(RetiredSlotId::R11),
        "r12" | "8d" => SlotId::Retired(RetiredSlotId::R12),
        "r13" | "8e" => SlotId::Retired(RetiredSlotId::R13),
        "r14" | "8f" => SlotId::Retired(RetiredSlotId::R14),
        "r15" | "90" => SlotId::Retired(RetiredSlotId::R15),
        "r16" | "91" => SlotId::Retired(RetiredSlotId::R16),
        "r17" | "92" => SlotId::Retired(RetiredSlotId::R17),
        "r18" | "93" => SlotId::Retired(RetiredSlotId::R18),
        "r19" | "94" => SlotId::Retired(RetiredSlotId::R19),
        "r20" | "95" => SlotId::Retired(RetiredSlotId::R20),
        _ => return simple_error!("Unknown slot: {}", slot),
    })
}