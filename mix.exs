defmodule Zerossl.MixProject do
  use Mix.Project

  def project do
    [
      app: :zerossl,
      version: "1.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      # Docs
      name: "zerossl",
      source_url: "https://github.com/riccard.manfrin/zerossl",
      docs: [
        # The main page in the docs
        main: "readme",
        # logo: "path/to/logo.png",
        extras: ["README.md"]
      ],
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: extra_applications(Mix.env()),
      mod: {ZerosslSup, []}
    ]
  end

  defp elixirc_paths(env) when env in [:dev, :test], do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp extra_applications(env) when env in [:dev, :test],
    do: [:logger, :inets, :observer, :wx, :runtime_tools]

  defp extra_applications(_), do: [:logger, :inets]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:httpoison, "~> 2.0"},
      {:jason, "~> 1.4"},
      {:x509, "~> 0.8"},

      # Non prod
      {:ex_doc, "~> 0.30", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
  defp package() do
    [
      name: "zerossl",
      licenses: ["MIT"],
      description: "Provides zerossl and letsencrypt (and letsencrypt-testing) SSL certs management automation",
      links: %{"GitHub" => "https://github.com/riccardomanfrin/zerossl"}
    ]
  end
end
