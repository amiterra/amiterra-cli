use super::api::BootstrapPayload;

pub fn check_cloud_init() -> Option<BootstrapPayload> {
    // Future: read /var/lib/cloud/instance/user-data
    None
}

pub fn check_cmdline() -> Option<BootstrapPayload> {
    // Future: parse /proc/cmdline
    None
}
