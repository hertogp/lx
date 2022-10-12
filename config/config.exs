import Config

config :logger,
  level: :info

config :logger, :console,
  format: {Lx, :format},
  metadata: [:module],
  colors: [enabled: true],
  level: :debug,
  device: :standard_error
