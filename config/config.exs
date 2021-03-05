import Config

config :logger,
       :console,
       format: {Lx, :format},
       truncate: 2056,
       metadata: [:cmd],
       colors: [enabled: true]
