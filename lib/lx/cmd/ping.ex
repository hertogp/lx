defmodule Lx.Cmd.Ping do
  def run(arg, _opts \\ []) do
    t =
      if "127.0.0.1" == arg,
        do: 10000,
        else: :rand.uniform(4000)

    Process.sleep(t)

    case arg do
      "127.0.0.2" ->
        raise ArgumentError, arg

      "127.0.0.3" ->
        exit({:kaboom, arg})

      _ ->
        # IO.puts("#{Lx.Cmd.Control.active()} - ping #{arg} done")
        Lx.Cmd.Control.done(self())
        {:ok, {arg, t}}
    end
  end
end
