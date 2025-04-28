//! Strace related code

use std::{collections::HashMap, fmt, io::BufRead as _, process::Command, str};

mod parser;
mod run;

pub(crate) use run::Strace;

const STRACE_BIN: &str = if let Some(p) = option_env!("SHH_STRACE_BIN_PATH") {
    p
} else {
    "strace"
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Syscall {
    pub pid: u32,
    pub rel_ts: f64,
    pub name: String,
    pub args: Vec<Expression>,
    pub ret_val: IntegerExpression,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BufferType {
    AbstractPath,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IntegerExpression {
    pub value: IntegerExpressionValue,
    pub metadata: Option<Vec<u8>>,
}

impl IntegerExpression {
    pub(crate) fn value(&self) -> Option<i128> {
        self.value.value()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BufferExpression {
    pub value: Vec<u8>,
    pub type_: BufferType,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Expression {
    Buffer(BufferExpression),
    Integer(IntegerExpression),
    Struct(HashMap<String, Expression>),
    // The strace syntax can be ambiguous between array and set (ie sigset_t in sigprocmask),
    // so store both in this, and let the summary interpret
    Collection {
        complement: bool,
        // First element of tuple is index if explicitly set
        values: Vec<(Option<IntegerExpression>, Expression)>,
    },
    Macro {
        name: String,
        args: Vec<Expression>,
    },
    // Only used for strace pseudo macro invocations, see `test_macro_addr_arg` for an example
    DestinationAddress(String),
}

impl Expression {
    pub(crate) fn metadata(&self) -> Option<&[u8]> {
        match self {
            Self::Integer(IntegerExpression { metadata, .. }) => metadata.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IntegerExpressionValue {
    BinaryOr(Vec<IntegerExpressionValue>),
    Multiplication(Vec<IntegerExpressionValue>),
    LeftBitShift {
        bits: Box<IntegerExpressionValue>,
        shift: Box<IntegerExpressionValue>,
    },
    NamedConst(String),
    Literal(i128), // allows holding both signed and unsigned 64 bit integers
}

impl IntegerExpressionValue {
    pub(crate) fn is_flag_set(&self, flag: &str) -> bool {
        match self {
            IntegerExpressionValue::NamedConst(v) => flag == v,
            IntegerExpressionValue::BinaryOr(ces) => ces.iter().any(|ce| ce.is_flag_set(flag)),
            _ => false, // if it was a flag field, strace would have decoded it with named consts
        }
    }

    pub(crate) fn flags(&self) -> Vec<String> {
        match self {
            IntegerExpressionValue::NamedConst(v) => vec![v.clone()],
            IntegerExpressionValue::BinaryOr(vs) => {
                vs.iter().flat_map(IntegerExpressionValue::flags).collect()
            }
            _ => vec![],
        }
    }

    pub(crate) fn value(&self) -> Option<i128> {
        match self {
            IntegerExpressionValue::BinaryOr(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| a | b),
            IntegerExpressionValue::Multiplication(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| a * b),
            IntegerExpressionValue::LeftBitShift { bits, shift } => {
                Some(bits.value()? << shift.value()?)
            }
            IntegerExpressionValue::NamedConst(_) => None,
            IntegerExpressionValue::Literal(v) => Some(*v),
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct StraceVersion {
    pub major: u16,
    pub minor: u16,
}

impl StraceVersion {
    pub(crate) fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub(crate) fn local_system() -> anyhow::Result<Self> {
        let output = Command::new(STRACE_BIN).arg("--version").output()?;
        if !output.status.success() {
            anyhow::bail!("strace invocation failed with code {:?}", output.status);
        }
        let version_line = output
            .stdout
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))??;
        let (major, minor) = version_line
            .rsplit_once(' ')
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))?
            .1
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))?;
        Ok(Self {
            major: major.parse()?,
            minor: minor.parse()?,
        })
    }
}

impl fmt::Display for StraceVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}
