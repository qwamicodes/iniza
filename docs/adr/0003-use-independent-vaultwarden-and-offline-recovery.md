# Use independent Vaultwarden and offline recovery methods

Each Bundle has independently derived recovery slots for a generated Vaultwarden Recovery Secret and a separately stored Offline Recovery Key. Iniza integrates with the owner's external Vaultwarden service through the official Bitwarden `bw` CLI rather than implementing the server protocol or holding a master password; either recovery method must unlock the Bundle without depending on the other.
