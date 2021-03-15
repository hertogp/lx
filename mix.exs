defmodule Lx.MixProject do
  use Mix.Project

  def project do
    [
      app: :lx,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      escript: [main_module: Lx.Cmd, strip_beams: [keep: "Docs"]],
      deps: deps(),
      xref: [exclude: [IEx, :epp_dodger]]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.18", only: :dev, runtime: false},
      {:credo, "~> 1.5", only: [:dev, :test]},
      {:easy_ssl, "~> 1.3.0"}
    ]
  end
end
