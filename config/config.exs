import Config

config :logger,
       :console,
       format: {Lx, :format},
       truncate: 2056,
       metadata: [:module],
       colors: [enabled: true]
