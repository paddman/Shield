# Deception Tripwire Response

## Trigger
A canary credential, decoy share, fake API token, honey file, or decoy service is accessed.

## Interpretation
A properly placed deception token should have almost no legitimate use. Treat a hit as high confidence while still validating scanner, backup, indexing, and test activity.

## Respond
1. Preserve all telemetry immediately.
2. Identify source host, user, process, service, network path, and preceding activity.
3. Isolate or block only through the human approval gate.
4. Hunt for the same user, process, hash, and destination across the fleet.
5. Rotate any real secrets located near the decoy.
