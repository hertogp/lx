defmodule Lx.Cmd.Port do
  require Logger

  def run(argv) do
    {host, port, status} =
      case argv do
        [] -> Logger.error("Need (hostname, portnr)")
        [host] -> get(host, 80)
        [host, port] -> get(host, String.to_integer(port))
        _ -> Logger.error("ArgError #{inspect(argv)}")
      end

    Logger.info("#{host} #{port}/tcp #{status}")
  end

  def get(hostname, port) do
    Logger.info("hostname: #{inspect(hostname)}, port: #{inspect(port)}")
    host = to_charlist(hostname)

    case :gen_tcp.connect(host, port, [active: false], 500) do
      {:ok, sock} ->
        :gen_tcp.close(sock)
        {hostname, port, "UP"}

      {:error, reason} ->
        {hostname, port, reason}
    end
  end
end
