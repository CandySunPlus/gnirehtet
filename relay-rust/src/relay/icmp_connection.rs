use crate::relay::udp_connection::Rc;
use std::rc::Rc;
use log::*;

const TAG: &'static str = "IcmpConnection";

pub struct IcmpConnection {

}

impl IcmpConnection {
    pub fn create() -> io::Result<Rc<RefCell<Self>>> {
        cx_info!(target: TAG, id, "Open");
    }
}

