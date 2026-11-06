//! Systemd unit configuration

use std::str;

use anyhow::Context as _;

/// Characters systemd strips around lines, keys and values
const WHITESPACE: [char; 4] = [' ', '\t', '\n', '\r'];
/// UTF-8 byte order mark
const BOM: &[u8] = b"\xef\xbb\xbf";
/// Characters systemd forbids in section names, besides control characters
const SECTION_NAME_FORBIDDEN_CHARS: [char; 6] = ['\\', '"', '\'', '*', '?', '['];

/// Unit section and its key/value assignments
struct Section {
    name: String,
    assignments: Vec<(String, String)>,
}

/// Unit configuration, as sections in load order
#[derive(Default)]
pub(crate) struct UnitConfig(Vec<Section>);

impl UnitConfig {
    /// Parse a unit file and append its sections, following systemd's `config_parse()`
    ///
    /// On error, the lines before the failing one stay applied.
    pub(crate) fn add_file(&mut self, content: &[u8]) -> anyhow::Result<()> {
        let mut in_section = false;
        let mut logical_line = Vec::new();
        for line in content.split(|&b| b == b'\n') {
            // Comment lines are ignored, even within a continuation
            let first_char = line.iter().find(|&&b| !WHITESPACE.contains(&char::from(b)));
            if matches!(first_char, Some(b'#' | b';')) {
                continue;
            }
            logical_line.extend_from_slice(line.strip_prefix(BOM).unwrap_or(line));
            let trailing_backslashes = logical_line
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            if trailing_backslashes.is_multiple_of(2) {
                self.parse_line(&logical_line, &mut in_section)?;
                logical_line.clear();
            } else {
                // Continuation, trailing '\' becomes a space
                logical_line.pop();
                logical_line.push(b' ');
            }
        }
        self.parse_line(&logical_line, &mut in_section)
    }

    /// Parse a line with its continuations joined, following systemd's `parse_line()`
    fn parse_line(&mut self, line: &[u8], in_section: &mut bool) -> anyhow::Result<()> {
        let line = str::from_utf8(line)?.trim_matches(WHITESPACE);
        if let Some(header) = line.strip_prefix('[') {
            let name = header
                .strip_suffix(']')
                .filter(|name| {
                    !name.is_empty()
                        && !name.contains(|c: char| {
                            c.is_ascii_control() || SECTION_NAME_FORBIDDEN_CHARS.contains(&c)
                        })
                })
                .with_context(|| format!("Invalid section header {line:?}"))?;
            self.0.push(Section {
                name: name.to_owned(),
                assignments: Vec::new(),
            });
            *in_section = true;
        } else if let (Some(section), Some((key, value))) = (
            // Like systemd, ignore lines without '=', and assignments before the file's first section
            self.0.last_mut().filter(|_| *in_section),
            line.split_once('='),
        ) {
            section.assignments.push((
                key.trim_end_matches(WHITESPACE).to_owned(),
                value.trim_start_matches(WHITESPACE).to_owned(),
            ));
        }
        Ok(())
    }

    /// Get the values of a setting, since its last reset by an empty assignment
    pub(crate) fn values(&self, section: &str, key: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|s| s.name == section)
            .flat_map(|s| &s.assignments)
            .filter(|(k, _)| k == key)
            .fold(Vec::new(), |mut vals, (_, v)| {
                // Handles lines that reset previously set options
                if v.is_empty() {
                    vals.clear();
                } else {
                    vals.push(v.as_str());
                }
                vals
            })
    }

    /// Check whether a section is present
    pub(crate) fn has_section(&self, name: &str) -> bool {
        self.0.iter().any(|s| s.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &[u8]) -> UnitConfig {
        let mut config = UnitConfig::default();
        config.add_file(content).unwrap();
        config
    }

    #[test]
    fn values_whitespace() {
        let config = parse(
            b"[Service]\n\tExecStart = /bin/foo \t\nExecStartPre=/bin/sh -c \"a \\\n    b\"\nType\xc2\xa0=simple\n",
        );
        assert_eq!(config.values("Service", "ExecStart"), vec!["/bin/foo"]);
        assert_eq!(
            config.values("Service", "ExecStartPre"),
            vec!["/bin/sh -c \"a      b\""]
        );
        assert_eq!(config.values("Service", "Type"), Vec::<&str>::new());
    }

    #[test]
    fn values_reset() {
        let config = parse(
            b"[Service]\nblah=a\nblah=b\nblah=\nblah=c\nblih=e\nbloh=f\nblah=d\nbluh=a\nbluh = \n",
        );
        assert_eq!(config.values("Service", "blah"), vec!["c", "d"]);
        assert_eq!(config.values("Service", "bluh"), Vec::<&str>::new());
    }

    #[test]
    fn values_multiline() {
        let config = parse(
            br#"[Service]
ExecStartPre=/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= || \
VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ] \
&& systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1"
"#,
        );
        assert_eq!(
            config.values("Service", "ExecStartPre"),
            vec![
                r#"/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= ||  VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ]  && systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1""#
            ]
        );
        assert_eq!(
            parse(b"[Service]\nA=1\\\\\nA=2\n").values("Service", "A"),
            vec![r"1\\", "2"]
        );
        assert_eq!(parse(b"[Service]\nA=1\\").values("Service", "A"), vec!["1"]);
    }

    #[test]
    fn values_sections() {
        let config = parse(
            b"ExecStart=/bin/a\n[Unit]\nExecStart=/bin/b\n  [Service]  \nExecStart=/bin/c\n[X-Container]\nExecStart=/bin/d\n[Service]\nExecStart=/bin/e\n",
        );
        assert_eq!(
            config.values("Service", "ExecStart"),
            vec!["/bin/c", "/bin/e"]
        );
        assert!(config.has_section("X-Container"));
        assert!(!config.has_section("Container"));
    }

    #[test]
    fn values_bom() {
        let config = parse(b"\xef\xbb\xbf[Service]\nExecStart=/bin/foo\n");
        assert_eq!(config.values("Service", "ExecStart"), vec!["/bin/foo"]);
    }

    #[test]
    fn add_file_headerless_dropin() {
        let mut config = parse(b"[Service]\nExecStart=/bin/true\n");
        config
            .add_file(b"ExecStart=\nExecStart=/bin/false\n")
            .unwrap();
        assert_eq!(config.values("Service", "ExecStart"), vec!["/bin/true"]);
    }

    #[test]
    fn add_file_invalid_utf8() {
        let mut config = UnitConfig::default();
        assert!(
            config
                .add_file(b"[Service]\nExecStart=/bin/a\nEnvironment=A=\xff\nExecStart=/bin/b\n")
                .is_err()
        );
        assert_eq!(config.values("Service", "ExecStart"), vec!["/bin/a"]);
    }

    #[test]
    fn add_file_invalid_section_header() {
        for header in [
            "[Service",
            "[]",
            "[X-\"Metadata\"]",
            "[A\\B]",
            "[A*]",
            "[A\tB]",
        ] {
            let mut config = UnitConfig::default();
            assert!(
                config
                    .add_file(
                        format!("[Service]\nExecStart=/bin/a\n{header}\nExecStart=/bin/b\n")
                            .as_bytes()
                    )
                    .is_err()
            );
            assert_eq!(config.values("Service", "ExecStart"), vec!["/bin/a"]);
        }
    }

    #[test]
    fn systemd_test_cases() {
        // From systemd's src/test/test-conf-parser.c
        for (input, expected) in [
            ("[Section]\nsetting1=1\n", vec!["1"]),
            ("[Section]\nsetting1=1", vec!["1"]),
            ("\n\n\n\n[Section]\n\n\nsetting1=1", vec!["1"]),
            (
                "[Section]\n[Section]\nsetting1=1\nsetting1=    2 \t\nsetting1=    1\n",
                vec!["1", "2", "1"],
            ),
            (
                "[Section]\n[Section]\nsetting1=1\nsetting1=2\\\n   \nsetting1=1\n",
                vec!["1", "2", "1"],
            ),
            ("[Section]\nsetting1=1\\\n2\\\n3\n", vec!["1 2 3"]),
            (
                "[Section]\n#hogehoge\\\nsetting1=1\\\n2\\\n3\n",
                vec!["1 2 3"],
            ),
            (
                "[Section]\nsetting1=1\\\n#hogehoge\\\n2\\\n3\n",
                vec!["1 2 3"],
            ),
            (
                "[Section]\n   #hogehoge\\\n   setting1=1\\\n2\\\n3\n",
                vec!["1 2 3"],
            ),
            (
                "[Section]\n   setting1=1\\\n   #hogehoge\\\n2\\\n3\n",
                vec!["1 2 3"],
            ),
            ("[Section]\nsetting1=1\\\n2\\\n3\\\n", vec!["1 2 3"]),
            ("[Section]\nsetting1=1\\\\\\\n\\\\2\n", vec!["1\\\\ \\\\2"]),
            (
                "[Section]\nsetting1=2\n[NoWarnSection]\nsetting1=3\n[WarnSection]\nsetting1=3\n[X-Section]\nsetting1=3\n",
                vec!["2"],
            ),
        ] {
            assert_eq!(
                parse(input.as_bytes()).values("Section", "setting1"),
                expected
            );
        }
    }
}
