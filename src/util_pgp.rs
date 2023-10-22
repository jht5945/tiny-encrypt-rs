use openpgp_card::{OpenPgp, OpenPgpTransaction};
use openpgp_card_pcsc::PcscBackend;
use rust_util::{failure, opt_result, opt_value_result, simple_error, success, warning, XResult};

use crate::util;

pub fn read_and_verify_openpgp_pin(trans: &mut OpenPgpTransaction, pin: &Option<String>) -> XResult<()> {
    let pin = util::read_pin(pin);
    if let Err(e) = trans.verify_pw1_user(pin.as_ref()) {
        failure!("Verify user pin failed: {}", e);
        return simple_error!("User pin verify failed: {}", e);
    }
    success!("User pin verify success!");
    util::zeroize(pin);
    Ok(())
}

pub fn get_openpgp() -> XResult<OpenPgp> {
    let card = match get_card() {
        Err(e) => {
            return simple_error!("Get card failed: {}", e);
        }
        Ok(card) => card
    };
    Ok(OpenPgp::new(card))
}

pub fn get_card() -> XResult<PcscBackend> {
    let card_list = opt_result!(
        PcscBackend::cards(None), "Read OpenPGP card list failed: {}"
    );
    if card_list.is_empty() {
        return simple_error!("Cannot find any card");
    }
    if card_list.len() > 1 {
        warning!("Find {} OpenPGP cards, will use first card", card_list.len());
    }
    Ok(opt_value_result!(card_list.into_iter().next(), "SHOULD NOT HAPPEN, CANNOT FIND ANY CARD"))
}
