//! Whether the SMBIOS strings say a virtual machine: [`VM_RULES`].
//!
//! Four strings are looked at (the System Information maker and product, type 1, and the BIOS
//! vendor and version, type 0), trimmed and lowercased, each against the words hypervisors and the clouds
//! built on them write there by default. A match only sends the PC to an admin's review (the server's
//! `device_hw.vm`); nothing is refused by it. So each rule is one a real PC's firmware does not use:
//! «Microsoft Corporation» alone is a Surface, «Virtual Machine» is Hyper-V; «Phoenix» is VMware's
//! old BIOS and a thousand laptops', so it is not here. A hypervisor told to write a real maker's
//! strings is not caught, and need not be: the fingerprint is a fact, not a gate.

use crate::smbios::Smbios;

/// The SMBIOS string a rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmField {
    /// Type 1, offset 04h: «Manufacturer».
    SystemManufacturer,
    /// Type 1, offset 05h: «Product Name».
    SystemProduct,
    /// Type 0, offset 04h: «Vendor».
    BiosVendor,
    /// Type 0, offset 05h: «BIOS Version».
    BiosVersion,
}

/// How a rule matches the string, trimmed and lowercased; the needle is lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmMatch {
    Exact(&'static str),
    Prefix(&'static str),
    Contains(&'static str),
}

impl VmMatch {
    fn matches(self, value: &str) -> bool {
        match self {
            Self::Exact(n) => value == n,
            Self::Prefix(n) => value.starts_with(n),
            Self::Contains(n) => value.contains(n),
        }
    }
}

/// One row: which hypervisor (`family`, the log's `vm_by`), what it reads, how, and a string that
/// hypervisor writes (`example`, the row's own test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmRule {
    pub family: &'static str,
    pub field: VmField,
    pub matches: VmMatch,
    pub example: &'static str,
}

const fn rule(
    family: &'static str,
    field: VmField,
    matches: VmMatch,
    example: &'static str,
) -> VmRule {
    VmRule {
        family,
        field,
        matches,
        example,
    }
}

use VmField::{BiosVendor, BiosVersion, SystemManufacturer, SystemProduct};
use VmMatch::{Contains, Exact, Prefix};

/// Every rule, the first match wins (each family's rows together).
pub const VM_RULES: &[VmRule] = &[
    // VMware Workstation, Player, Fusion, ESXi.
    rule(
        "vmware",
        SystemManufacturer,
        Prefix("vmware"),
        "VMware, Inc.",
    ),
    rule("vmware", SystemProduct, Prefix("vmware"), "VMware20,1"),
    rule(
        "vmware",
        SystemProduct,
        Prefix("vmware"),
        "VMware Virtual Platform",
    ),
    rule("vmware", BiosVendor, Prefix("vmware"), "VMware, Inc."),
    // VirtualBox: still innotek's name in the firmware.
    rule(
        "virtualbox",
        SystemManufacturer,
        Exact("innotek gmbh"),
        "innotek GmbH",
    ),
    rule(
        "virtualbox",
        SystemProduct,
        Exact("virtualbox"),
        "VirtualBox",
    ),
    rule(
        "virtualbox",
        BiosVendor,
        Exact("innotek gmbh"),
        "innotek GmbH",
    ),
    rule("virtualbox", BiosVersion, Exact("virtualbox"), "VirtualBox"),
    // QEMU and KVM (Proxmox, UTM, libvirt): the machine's own words, and its two firmwares.
    rule("qemu", SystemManufacturer, Exact("qemu"), "QEMU"),
    rule(
        "qemu",
        SystemProduct,
        Prefix("standard pc ("),
        "Standard PC (Q35 + ICH9, 2009)",
    ),
    rule(
        "qemu",
        SystemProduct,
        Prefix("standard pc ("),
        "Standard PC (i440FX + PIIX, 1996)",
    ),
    rule("qemu", SystemProduct, Exact("kvm"), "KVM"),
    rule("qemu", BiosVendor, Exact("seabios"), "SeaBIOS"),
    rule(
        "qemu",
        BiosVendor,
        Contains("ovmf"),
        "EFI Development Kit II / OVMF",
    ),
    // Hyper-V, Azure, Virtual PC: «Microsoft Corporation» / «Virtual Machine». The maker alone is
    // also every Surface, so only the product and the firmware's version count.
    rule(
        "hyper-v",
        SystemProduct,
        Exact("virtual machine"),
        "Virtual Machine",
    ),
    rule(
        "hyper-v",
        BiosVersion,
        Prefix("hyper-v"),
        "Hyper-V UEFI Release v4.1",
    ),
    // Xen, and the EC2 instances that ran on it.
    rule("xen", SystemManufacturer, Exact("xen"), "Xen"),
    rule("xen", SystemProduct, Exact("hvm domu"), "HVM domU"),
    rule("xen", BiosVendor, Exact("xen"), "Xen"),
    // Parallels Desktop (Windows on a Mac).
    rule(
        "parallels",
        SystemManufacturer,
        Prefix("parallels"),
        "Parallels Software International Inc.",
    ),
    rule(
        "parallels",
        SystemManufacturer,
        Prefix("parallels"),
        "Parallels International GmbH.",
    ),
    rule(
        "parallels",
        SystemProduct,
        Prefix("parallels"),
        "Parallels Virtual Platform",
    ),
    rule(
        "parallels",
        BiosVendor,
        Prefix("parallels"),
        "Parallels Software International Inc.",
    ),
    // Bochs.
    rule("bochs", SystemManufacturer, Exact("bochs"), "Bochs"),
    rule("bochs", SystemProduct, Exact("bochs"), "Bochs"),
    rule("bochs", BiosVendor, Exact("bochs"), "Bochs"),
    // bhyve (FreeBSD).
    rule("bhyve", SystemProduct, Exact("bhyve"), "BHYVE"),
    rule("bhyve", BiosVendor, Exact("bhyve"), "BHYVE"),
    // Clouds whose own hypervisor writes its name.
    rule(
        "amazon-ec2",
        SystemManufacturer,
        Exact("amazon ec2"),
        "Amazon EC2",
    ),
    rule(
        "google-compute-engine",
        SystemProduct,
        Exact("google compute engine"),
        "Google Compute Engine",
    ),
    rule(
        "digitalocean",
        SystemManufacturer,
        Exact("digitalocean"),
        "DigitalOcean",
    ),
    rule(
        "openstack",
        SystemProduct,
        Exact("openstack nova"),
        "OpenStack Nova",
    ),
    rule(
        "openstack",
        SystemManufacturer,
        Exact("openstack foundation"),
        "OpenStack Foundation",
    ),
    rule(
        "alibaba-cloud",
        SystemProduct,
        Exact("alibaba cloud ecs"),
        "Alibaba Cloud ECS",
    ),
];

/// The family of the first rule `table`'s strings match; `None` for none.
pub(crate) fn signal(table: &Smbios) -> Option<&'static str> {
    let read = |field: VmField| -> Option<String> {
        let value = match field {
            SystemManufacturer => table.system_manufacturer.as_deref(),
            SystemProduct => table.system_product.as_deref(),
            BiosVendor => table.bios_vendor.as_deref(),
            BiosVersion => table.bios_version.as_deref(),
        }?;
        Some(value.trim().to_ascii_lowercase())
    };
    let fields = [SystemManufacturer, SystemProduct, BiosVendor, BiosVersion].map(|f| (f, read(f)));
    VM_RULES
        .iter()
        .find(|r| {
            fields
                .iter()
                .any(|(f, v)| *f == r.field && v.as_deref().is_some_and(|v| r.matches.matches(v)))
        })
        .map(|r| r.family)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(field: VmField, value: &str) -> Smbios {
        let mut t = Smbios::empty();
        let v = Some(value.to_string());
        match field {
            SystemManufacturer => t.system_manufacturer = v,
            SystemProduct => t.system_product = v,
            BiosVendor => t.bios_vendor = v,
            BiosVersion => t.bios_version = v,
        }
        t
    }

    #[test]
    fn every_row_matches_its_example_alone_and_in_any_case() {
        for r in VM_RULES {
            for spelling in [
                r.example.to_string(),
                r.example.to_uppercase(),
                format!("  {}  ", r.example),
            ] {
                assert_eq!(
                    signal(&with(r.field, &spelling)),
                    Some(r.family),
                    "{r:?} with {spelling:?}"
                );
            }
            // The example is what the needle was written for.
            assert!(
                r.matches.matches(&r.example.trim().to_ascii_lowercase()),
                "{r:?}: the example fits its own needle"
            );
        }
    }

    #[test]
    fn the_needles_are_lowercase_and_the_families_named() {
        for r in VM_RULES {
            let (VmMatch::Exact(n) | VmMatch::Prefix(n) | VmMatch::Contains(n)) = r.matches;
            assert!(!n.is_empty(), "{r:?}");
            assert_eq!(n, n.to_ascii_lowercase(), "{r:?}: needles are lowercase");
            assert_eq!(n, n.trim(), "{r:?}");
            assert!(
                !r.family.is_empty()
                    && r.family
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{r:?}: the family is a plain label (it goes into the log)"
            );
        }
    }

    /// What real PCs' firmware says: none of it is a virtual machine.
    #[test]
    fn real_hardware_is_not_a_vm() {
        let pcs: &[(&str, &str, &str, &str)] = &[
            (
                "Micro-Star International Co., Ltd.",
                "MS-7C91",
                "American Megatrends International, LLC.",
                "A.D0",
            ),
            (
                "ASUS",
                "System Product Name",
                "American Megatrends Inc.",
                "2803",
            ),
            (
                "System manufacturer",
                "System Product Name",
                "American Megatrends Inc.",
                "0605",
            ),
            (
                "Gigabyte Technology Co., Ltd.",
                "B550 AORUS ELITE",
                "American Megatrends International, LLC.",
                "F15",
            ),
            (
                "To Be Filled By O.E.M.",
                "To Be Filled By O.E.M.",
                "American Megatrends Inc.",
                "P2.10",
            ),
            ("Dell Inc.", "XPS 15 9520", "Dell Inc.", "1.21.0"),
            ("LENOVO", "20XW0055RT", "LENOVO", "N32ET86W (1.62 )"),
            ("HP", "HP Pavilion Gaming Laptop 15-ec2xxx", "AMI", "F.21"),
            (
                "Microsoft Corporation",
                "Surface Pro 8",
                "Microsoft Corporation",
                "20.100.143",
            ),
            (
                "Microsoft Corporation",
                "Surface Laptop Studio",
                "Microsoft Corporation",
                "18.3.140",
            ),
            (
                "Apple Inc.",
                "MacBookPro15,1",
                "Apple Inc.",
                "1554.140.20.0.0 (iBridge: 19.16.15071.0.0,0)",
            ),
            ("Acer", "Nitro AN515-58", "Insyde Corp.", "V1.15"),
            ("HUAWEI", "KLVL-WXX9", "HUAWEI", "1.24"),
            (
                "Phoenix Technologies Ltd.",
                "Notebook",
                "Phoenix Technologies LTD",
                "6.00",
            ),
            ("coreboot", "Librem 14", "coreboot", "4.17-Purism-1"),
        ];
        for (maker, product, vendor, version) in pcs {
            let t = Smbios {
                system_manufacturer: Some((*maker).into()),
                system_product: Some((*product).into()),
                bios_vendor: Some((*vendor).into()),
                bios_version: Some((*version).into()),
                ..Smbios::empty()
            };
            assert_eq!(
                signal(&t),
                None,
                "{maker} / {product} / {vendor} / {version}"
            );
        }
        assert_eq!(signal(&Smbios::empty()), None, "nothing read: no signal");
    }

    /// Hyper-V as it reads whole: the maker a Surface shares, the product that is not.
    #[test]
    fn hyper_v_whole_and_its_maker_alone() {
        let hyper_v = Smbios {
            system_manufacturer: Some("Microsoft Corporation".into()),
            system_product: Some("Virtual Machine".into()),
            bios_vendor: Some("Microsoft Corporation".into()),
            bios_version: Some("Hyper-V UEFI Release v4.1".into()),
            ..Smbios::empty()
        };
        assert_eq!(signal(&hyper_v), Some("hyper-v"));
        assert_eq!(
            signal(&with(SystemManufacturer, "Microsoft Corporation")),
            None
        );
    }
}
