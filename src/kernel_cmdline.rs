// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recognition of Linux kernel arguments (lib/cmdline.c and kernel/params.c).

pub(crate) struct KernelCommandLine<'a>(pub(crate) &'a [u8]);

impl KernelCommandLine<'_> {
    /// Linux's x86_64 and arm64 COMMAND_LINE_SIZE, including the terminating NUL.
    pub(crate) const CAPACITY: usize = 2048;

    pub(crate) fn bootconfig_requested(&self) -> bool {
        let mut rest = self.0.split(|&c| c == 0).next().unwrap_or_default();
        loop {
            rest = &rest[rest
                .iter()
                .position(|c| !Self::is_space(c))
                .unwrap_or(rest.len())..];
            if rest.is_empty() {
                return false;
            }
            let quoted = rest[0] == b'"';
            rest = &rest[usize::from(quoted)..];
            let mut in_quote = quoted;
            let mut equals = 0;
            let end = rest
                .iter()
                .enumerate()
                .find_map(|(i, &c)| {
                    if Self::is_space(&c) && !in_quote {
                        return Some(i);
                    }
                    if equals == 0 && c == b'=' {
                        equals = i;
                    }
                    if c == b'"' {
                        in_quote = !in_quote;
                    }
                    None
                })
                .unwrap_or(rest.len());
            let mut name = &rest[..if equals == 0 { end } else { equals }];
            if quoted && equals == 0 && name.last() == Some(&b'"') {
                name = &name[..name.len() - 1];
            }
            if equals == 0 && name == b"--" {
                return false;
            }
            if name == b"bootconfig" {
                return true;
            }
            rest = &rest[end..];
        }
    }

    fn is_space(c: &u8) -> bool {
        matches!(c, b' ' | b'\t'..=b'\r' | 0xa0)
    }
}

#[cfg(test)]
mod tests {
    use super::KernelCommandLine;

    #[test]
    fn recognizes_linux_bootconfig_arguments() {
        for cmdline in [
            "bootconfig",
            "console=hvc0 bootconfig quiet",
            "bootconfig=0",
            "bootconfig=off",
            "bootconfig=",
            "bootconfig=\"value with spaces\"",
            "\"bootconfig\"",
            "\"bootconfig=0\"",
            "bootconfig -- init-argument",
            "bootconfig bootconfig",
            "foo=\"--\" bootconfig",
            "--=value bootconfig",
            "\t\r\n\u{b}\u{c}bootconfig\t",
            "bootconfig\0ignored",
        ] {
            assert!(
                KernelCommandLine(cmdline.as_bytes()).bootconfig_requested(),
                "{cmdline:?}"
            );
        }
    }

    #[test]
    fn ignores_values_init_arguments_and_other_names() {
        for cmdline in [
            "",
            "\t\r\n",
            "-- bootconfig",
            "\"--\" bootconfig",
            "foo=bootconfig",
            "foo=\"a bootconfig b\"",
            "\"bootconfig something\"",
            "'bootconfig'",
            "bootconfig-extra",
            "nobootconfig",
            "BOOTCONFIG",
            "bootconfig\"\"",
            "quiet\0 bootconfig",
            "foo=\"unterminated bootconfig",
        ] {
            assert!(
                !KernelCommandLine(cmdline.as_bytes()).bootconfig_requested(),
                "{cmdline:?}"
            );
        }
    }
}
