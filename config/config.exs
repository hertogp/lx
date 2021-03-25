import Config

config :logger, :console,
  format: {Lx, :format},
  metadata: [:module],
  colors: [enabled: true]

# level: :notice

# backends: [:console],

# Levels seem to be mapped to 1 of 4 levels:
# -----------------------------------------------------------------------------------
# ERROR   :emergency - when system is unusable, panics
# ERROR   :alert     - for alerts, actions that must be taken immediately, ex. corrupted database
# ERROR   :critical  - for critical conditions
# ERROR   :error     - for errors
# WARNING :warning   - for warnings
# INFO    :notice    - for normal, but significant, messages
# INFO    :info      - for information of any kind
# DEBUG   :debug     - for debug-related messages
