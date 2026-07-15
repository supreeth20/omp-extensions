export function resolveNetworkPolicy(policy: Record<string, unknown>, capabilities: Record<string, unknown>): Record<string, unknown> {
  const hasAllowedHosts = Array.isArray(policy.allowedHosts) && policy.allowedHosts.length > 0;
  const hasBlockedHosts = Array.isArray(policy.blockedHosts) && policy.blockedHosts.length > 0;
  const allowedHostsSupported = capabilities.hostRules === true || capabilities.allowedHosts === true;
  const blockedHostsSupported = capabilities.hostRules === true || capabilities.blockedHosts === true;
  if ((hasAllowedHosts && !allowedHostsSupported) || (hasBlockedHosts && !blockedHostsSupported)) {
    return {
      activation: "choice-required",
      choices: ["block-network", "allow-unrestricted-network", "cancel"],
      reason: "unsupported-host-rules",
    };
  }
  const coupledNetwork = capabilities.coupledNetwork === true;
  const networkEnabled = policy.internet === true || policy.localNetwork === true;
  return {
    activation: "ready",
    effective: {
      internet: coupledNetwork ? networkEnabled : policy.internet === true,
      localNetwork: coupledNetwork ? networkEnabled : policy.localNetwork === true,
      unrestricted: policy.unrestricted === true,
      ...(hasAllowedHosts ? { allowedHosts: structuredClone(policy.allowedHosts) } : {}),
      ...(hasBlockedHosts ? { blockedHosts: structuredClone(policy.blockedHosts) } : {}),
    },
  };
}
