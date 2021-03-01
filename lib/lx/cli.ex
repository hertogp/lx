defmodule Lx.CLI do
  def main(argv) do
    options = [
      switches: [file: :string],
      aliases: [f: :file]
    ]

    {opts, args, invalid} = OptionParser.parse(argv, options)
    IO.inspect(opts, label: "options")
    IO.inspect(args, label: "args")
    IO.inspect(invalid, label: "invalid")
  end
end
