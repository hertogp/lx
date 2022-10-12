defmodule Lx.Cmd.Port do
  @moduledoc """
  Port tries to connect to given `hostname` and `port` using tcp.

  It returns `{host, port, status}`, where status is either :up or
  some error message.

  """

  require Logger

  @match_port ~r/^\d+$/

  def setup(argv) do
    # run/1 expects [hostname, port]
    IO.inspect(argv)

    argv
    |> ensure_ports([])
    |> IO.inspect()
  end

  defp ensure_ports([host, port | rest], acc) do
    case port =~ @match_port do
      true -> ensure_ports(rest, [[host, port] | acc])
      false -> ensure_ports([port | rest], [[host, "80"] | acc])
    end
  end

  defp ensure_ports([host], acc) do
    case host =~ @match_port do
      true ->
        Logger.error("Missing hostname for port #{host}")
        acc

      false ->
        [[host, "80"] | acc]
    end
  end

  defp ensure_ports([], acc),
    do: acc

  def run(argv) do
    IO.inspect(argv)

    {host, port, status} =
      case argv do
        [] ->
          Logger.error("Need (hostname, portnr)")
          {nil, nil, :error}

        [host] ->
          get(host, 80)

        [host, port] ->
          get(host, String.to_integer(port))

        _ ->
          Logger.error("ArgError #{inspect(argv)}")
          {nil, nil, :error}
      end

    Logger.info("#{host} #{port}/tcp #{status}")
  end

  def get(hostname, port) do
    Logger.notice("hostname: #{inspect(hostname)}, port: #{inspect(port)}")
    host = to_charlist(hostname)

    case :gen_tcp.connect(host, port, [active: false], 500) do
      {:ok, sock} ->
        :gen_tcp.close(sock)
        {hostname, port, :up}

      {:error, reason} ->
        {hostname, port, reason}
    end
  end
end
