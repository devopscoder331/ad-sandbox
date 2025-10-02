#!/bin/sh

# Define the path to the secret file
SECRET_FILE="secrets/secret.txt"

# Check if the secret file exists and is not empty
if [ ! -f "$SECRET_FILE" ]; then
  # Create the secrets directory if it doesn't exist
  mkdir -p secrets

  # Generate a random secret and save it to the file
  head -c 32 /dev/urandom | base64 > "$SECRET_FILE"
  echo "Secret initialized and saved to $SECRET_FILE"
else
  echo "Using existing secret from $SECRET_FILE"
fi

# Read the secret from the file
SECRET=$(cat "$SECRET_FILE")

# Execute the mole_vault binary with the secret as a flag
exec ./mole_vault --secret-key="$SECRET"