defmodule Lx.Cmd.Http do
  @moduledoc """
  A simple GET of a url.

  Outputs the hostname, IP address, resource path & byte count of page retrieved.

  """
  require Logger

  def run(argv) do
    Logger.info(argv)
    IO.inspect(get(hd(argv)))
  end

  def get(hostname) do
    Logger.info("hostname: #{inspect(hostname)}")
    host = to_charlist(hostname)
    {:ok, sock} = :gen_tcp.connect(host, 80, active: false)
    ip = :inet.peername(sock)
    IO.inspect(:gen_tcp.send(sock, "GET /\r\n\r\n"))

    case :gen_tcp.recv(sock, 0, 2000) do
      {:error, reason} -> {hostname, ip, {:error, reason}}
      {:ok, binary} -> {hostname, ip, process(binary)}
    end
  end

  def process(binary) do
    case binary do
      "HTTP/1.0 200 OK" <> _ ->
        {"HTTP/1.0", 200, "OK", String.length(to_string(binary))}

      _ ->
        {"n/a", "NOK", "ERROR", String.length(to_string(binary))}
    end
  end
end
