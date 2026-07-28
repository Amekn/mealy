use crate::{EffectClass, PolicyProfile};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAXIMUM_SET_ITEMS: usize = 256;
const MAXIMUM_ITEM_BYTES: usize = 1_024;

/// Explicit authority envelope copied onto a parent or delegated run.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGrant {
    /// Stable tools that the run may request.
    pub tools: BTreeSet<String>,
    /// Effect classes that policy may authorize.
    pub effect_classes: BTreeSet<EffectClass>,
    /// Canonical workspace roots visible to the run.
    pub workspace_roots: BTreeSet<String>,
    /// Exact subset of logical workspace roots that may receive mutations.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub writable_workspace_roots: BTreeSet<String>,
    /// Exact outbound network destinations visible to the run.
    pub network_destinations: BTreeSet<String>,
    /// Exact executable content identities visible to process-capable runs.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub executable_identity_digests: BTreeSet<String>,
    /// Opaque secret references, never secret values.
    pub secret_references: BTreeSet<String>,
    /// Enforceable execution profiles available to the run.
    pub profiles: BTreeSet<PolicyProfile>,
    /// Maximum child runs this run may create in total.
    pub maximum_delegated_runs: u64,
    /// Maximum remaining child nesting levels below this run.
    pub maximum_delegation_depth: u64,
}

impl CapabilityGrant {
    /// Validates collection and item bounds without interpreting opaque capability names.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityGrantError`] for an empty, oversized, or non-canonical string item.
    pub fn validate(&self) -> Result<(), CapabilityGrantError> {
        for items in [
            &self.tools,
            &self.workspace_roots,
            &self.writable_workspace_roots,
            &self.network_destinations,
            &self.executable_identity_digests,
            &self.secret_references,
        ] {
            if items.len() > MAXIMUM_SET_ITEMS
                || items.iter().any(|item| {
                    item.is_empty()
                        || item.len() > MAXIMUM_ITEM_BYTES
                        || item.trim() != item
                        || item.chars().any(char::is_control)
                })
            {
                return Err(CapabilityGrantError::InvalidItem);
            }
        }
        if self.effect_classes.len() > MAXIMUM_SET_ITEMS || self.profiles.len() > MAXIMUM_SET_ITEMS
        {
            return Err(CapabilityGrantError::TooManyItems);
        }
        if !self
            .writable_workspace_roots
            .is_subset(&self.workspace_roots)
        {
            return Err(CapabilityGrantError::WritableWorkspaceOutsideGrant);
        }
        Ok(())
    }

    /// Computes the child authority as the intersection of parent, request, and current policy.
    ///
    /// Fan-out and depth are independent: creating a child consumes one depth level, while the
    /// child's own fan-out ceiling is the smallest explicitly granted total.
    #[must_use]
    pub fn intersect_for_child(&self, requested: &Self, policy: &Self) -> Self {
        Self {
            tools: intersection3(&self.tools, &requested.tools, &policy.tools),
            effect_classes: intersection3(
                &self.effect_classes,
                &requested.effect_classes,
                &policy.effect_classes,
            ),
            workspace_roots: intersection3(
                &self.workspace_roots,
                &requested.workspace_roots,
                &policy.workspace_roots,
            ),
            writable_workspace_roots: intersection3(
                &self.writable_workspace_roots,
                &requested.writable_workspace_roots,
                &policy.writable_workspace_roots,
            ),
            network_destinations: intersection3(
                &self.network_destinations,
                &requested.network_destinations,
                &policy.network_destinations,
            ),
            executable_identity_digests: intersection3(
                &self.executable_identity_digests,
                &requested.executable_identity_digests,
                &policy.executable_identity_digests,
            ),
            secret_references: intersection3(
                &self.secret_references,
                &requested.secret_references,
                &policy.secret_references,
            ),
            profiles: intersection3(&self.profiles, &requested.profiles, &policy.profiles),
            maximum_delegated_runs: self
                .maximum_delegated_runs
                .min(requested.maximum_delegated_runs)
                .min(policy.maximum_delegated_runs),
            maximum_delegation_depth: self
                .maximum_delegation_depth
                .saturating_sub(1)
                .min(requested.maximum_delegation_depth)
                .min(policy.maximum_delegation_depth),
        }
    }

    /// Returns whether every child authority dimension is contained by this grant.
    #[must_use]
    pub fn contains(&self, child: &Self) -> bool {
        child.tools.is_subset(&self.tools)
            && child.effect_classes.is_subset(&self.effect_classes)
            && child.workspace_roots.is_subset(&self.workspace_roots)
            && child
                .writable_workspace_roots
                .is_subset(&self.writable_workspace_roots)
            && child
                .network_destinations
                .is_subset(&self.network_destinations)
            && child
                .executable_identity_digests
                .is_subset(&self.executable_identity_digests)
            && child.secret_references.is_subset(&self.secret_references)
            && child.profiles.is_subset(&self.profiles)
            && child.maximum_delegated_runs <= self.maximum_delegated_runs
            && child.maximum_delegation_depth <= self.maximum_delegation_depth
    }
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct CapabilityGrantWire {
    tools: BTreeSet<String>,
    effect_classes: BTreeSet<EffectClass>,
    workspace_roots: BTreeSet<String>,
    writable_workspace_roots: BTreeSet<String>,
    network_destinations: BTreeSet<String>,
    executable_identity_digests: BTreeSet<String>,
    secret_references: BTreeSet<String>,
    profiles: BTreeSet<PolicyProfile>,
    maximum_delegated_runs: u64,
    maximum_delegation_depth: Option<u64>,
}

impl<'de> Deserialize<'de> for CapabilityGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CapabilityGrantWire::deserialize(deserializer)?;
        Ok(Self {
            tools: wire.tools,
            effect_classes: wire.effect_classes,
            workspace_roots: wire.workspace_roots,
            writable_workspace_roots: wire.writable_workspace_roots,
            network_destinations: wire.network_destinations,
            executable_identity_digests: wire.executable_identity_digests,
            secret_references: wire.secret_references,
            profiles: wire.profiles,
            maximum_delegated_runs: wire.maximum_delegated_runs,
            // Pre-v0.4 capability records did not carry an explicit depth. Preserve their exact
            // behavior: grants with child authority had one level; grants without it had none.
            maximum_delegation_depth: wire
                .maximum_delegation_depth
                .unwrap_or(u64::from(wire.maximum_delegated_runs > 0)),
        })
    }
}

fn intersection3<T: Clone + Ord>(
    first: &BTreeSet<T>,
    second: &BTreeSet<T>,
    third: &BTreeSet<T>,
) -> BTreeSet<T> {
    first
        .intersection(second)
        .filter(|item| third.contains(*item))
        .cloned()
        .collect()
}

/// Invalid delegated authority envelope.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityGrantError {
    /// A string capability is empty, unbounded, padded, or contains control characters.
    #[error("capability grant contains a non-canonical item")]
    InvalidItem,
    /// A capability dimension exceeds the bounded item count.
    #[error("capability grant contains too many items")]
    TooManyItems,
    /// A writable workspace was not also present in the general workspace authority set.
    #[error("writable workspace grant is outside the workspace authority set")]
    WritableWorkspaceOutsideGrant,
}

#[cfg(test)]
mod tests {
    use super::CapabilityGrant;
    use crate::{EffectClass, PolicyProfile};
    use std::collections::BTreeSet;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn child_authority_is_the_three_way_intersection() {
        let parent = CapabilityGrant {
            tools: set(&["read", "write"]),
            effect_classes: [EffectClass::ReadOnly, EffectClass::Idempotent]
                .into_iter()
                .collect(),
            workspace_roots: set(&["/a", "/b"]),
            writable_workspace_roots: set(&["/b"]),
            profiles: [PolicyProfile::Observe, PolicyProfile::WorkspaceWrite]
                .into_iter()
                .collect(),
            maximum_delegated_runs: 3,
            maximum_delegation_depth: 3,
            ..CapabilityGrant::default()
        };
        let requested = CapabilityGrant {
            tools: set(&["write", "admin"]),
            effect_classes: [EffectClass::Idempotent].into_iter().collect(),
            workspace_roots: set(&["/b", "/c"]),
            writable_workspace_roots: set(&["/b", "/c"]),
            profiles: [PolicyProfile::WorkspaceWrite].into_iter().collect(),
            maximum_delegated_runs: 2,
            maximum_delegation_depth: 2,
            ..CapabilityGrant::default()
        };
        let policy = CapabilityGrant {
            tools: set(&["read", "write"]),
            effect_classes: [EffectClass::Idempotent].into_iter().collect(),
            workspace_roots: set(&["/b"]),
            writable_workspace_roots: set(&["/b"]),
            profiles: [PolicyProfile::WorkspaceWrite].into_iter().collect(),
            maximum_delegated_runs: 2,
            maximum_delegation_depth: 1,
            ..CapabilityGrant::default()
        };
        let child = parent.intersect_for_child(&requested, &policy);
        assert_eq!(child.tools, set(&["write"]));
        assert_eq!(child.workspace_roots, set(&["/b"]));
        assert_eq!(child.writable_workspace_roots, set(&["/b"]));
        assert_eq!(child.maximum_delegated_runs, 2);
        assert_eq!(child.maximum_delegation_depth, 1);
        assert!(parent.contains(&child));
        assert!(requested.contains(&child));
        assert!(policy.contains(&child));
    }

    #[test]
    fn zero_delegation_authority_never_underflows() {
        let parent = CapabilityGrant::default();
        let child = parent.intersect_for_child(&parent, &parent);
        assert_eq!(child.maximum_delegated_runs, 0);
        assert_eq!(child.maximum_delegation_depth, 0);
        assert!(parent.contains(&child));
    }

    #[test]
    fn legacy_grants_infer_one_depth_only_when_they_had_child_authority() {
        let legacy_parent: CapabilityGrant =
            serde_json::from_str(r#"{"maximumDelegatedRuns":2}"#).expect("legacy parent");
        let legacy_leaf: CapabilityGrant =
            serde_json::from_str(r#"{"maximumDelegatedRuns":0}"#).expect("legacy leaf");
        assert_eq!(legacy_parent.maximum_delegation_depth, 1);
        assert_eq!(legacy_leaf.maximum_delegation_depth, 0);
        assert_eq!(
            serde_json::from_str::<CapabilityGrant>(
                &serde_json::to_string(&legacy_leaf).expect("serialize current leaf")
            )
            .expect("round trip current leaf")
            .maximum_delegation_depth,
            0
        );
    }
}
