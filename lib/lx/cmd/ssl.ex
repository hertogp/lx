defmodule Lx.Cmd.Ssl do
  @moduledoc """
  Worker that gathers and reports on a host's certificate chain (if any).

  Notes:
  - pulls cert chain off of a server by either name or IP address
  - if given an IP address, you might get a different cert than when using server name
    since a server may have several cert chains on-board for various names.

  TODO:
  - add more documentation
  - add qoutes around IP addresses in csv output so it wont end up as a number
  - output input arg consistently as a column in both console and csv output
  - add -i option to read names/IP's from a file
  - add -o option to append csv to a file (creating it if new)
  - add -q option to prevent any log messages
  - add -n option to specify hostname in addition to IP address (SNI)
    `-> sometimes names are not (yet) known in DNS
  - use IO list to dump strings to screen/csv
  - use NimbleCsv to dump csv to file (maybe?)
  - when arg is IP -> also get chain for subject name
  - always try to get chain for alt_names as well
  - a non-https server may reset the connection, I get :error 1 (wtf?)
  - a subject name could be a wildcard: subject *.waddenzee.nl
  """

  # See https://www.erlang.org/doc/man/ssl.html
  require Logger
  alias OptionParser

  @oids Lx.Utils.load_oids()
  @name __MODULE__

  @ssl_opts [
    versions: [:"tlsv1.1", :"tlsv1.2", :"tlsv1.3"],
    ciphers: :ssl.cipher_suites(:default, :"tlsv1.3"),
    depth: 99,
    verify: :verify_none,
    log_level: :none
  ]

  @cmd_opts [
    debug: :boolean,
    quiet: :boolean,
    csv: :boolean
  ]

  @cmd_aliases [
    d: :debug,
    q: :quiet,
    c: :csv
  ]

  @doc """
  Initialize module and parse arguments.
  """
  @spec setup([binary]) :: {[binary], Keyword.t()}
  def setup(argv) do
    {opts, args, invalid} = OptionParser.parse(argv, strict: @cmd_opts, aliases: @cmd_aliases)

    if Keyword.get(opts, :debug, false),
      do: Logger.configure_backend(:console, level: :debug),
      else: Logger.configure_backend(:console, level: :info)

    invalid
    |> Enum.map(fn x -> Logger.notice("ignoring unknown option #{inspect(x)}") end)

    # partial_chain stores the certificate chain in this registry (key = hash of end cert)
    Lx.Register.start_link(@name)

    args =
      args
      |> Enum.map(fn arg -> expand(arg) end)
      |> List.flatten()
      |> Enum.uniq()

    {args, opts}
  end

  def teardown(result, opts \\ []) do
    Logger.info("teardown ssl - pid: #{inspect(self())}, opts #{inspect(opts)}")
    Lx.Register.stop(@name)
    result
  end

  @doc """
  Run a worker for a single argument
  """
  def run(hostname, opts \\ []) do
    Logger.debug("running with -> #{inspect(hostname)}, opts: #{inspect(opts)}")

    host = to_charlist(hostname)

    ssl_opts =
      @ssl_opts
      |> Keyword.put(:partial_chain, &partial_chain/1)
      |> Keyword.put(:server_name_indication, host)

    # note: connect timeout should stay whithin Task timeout (10 sec)
    with(
      {:connect, {:ok, sock}} <- {:connect, :ssl.connect(host, 443, ssl_opts, 5_000)},
      {:cert, {:ok, der}} <- {:cert, :ssl.peercert(sock)},
      {:name, {:ok, {ip, port}}} <- {:name, :ssl.peername(sock)}
    ) do
      # get TLS version used
      {:ok, info} = :ssl.connection_information(sock)
      tlsv = Keyword.get(info, :protocol, "?")

      :ssl.close(sock)
      id = :crypto.hash(:sha256, der)

      ip =
        case Pfx.parse(ip) do
          {:ok, pfx} -> Pfx.format(pfx)
          {:error, _} -> "no ip"
        end

      chain =
        Lx.Register.get(@name, id, [der])
        |> Enum.reverse()
        |> Enum.map(fn cert -> der_decode(cert) end)

      {ip, port, tlsv, chain}
    else
      {:connect, {:error, reason}} ->
        {:error, "could not connect to #{hostname}: #{inspect(reason)}"}

      {:cert, error} ->
        {:error, "could not get peer cert for #{hostname}: #{inspect(error)}"}

      {:name, error} ->
        {:error, "could not get peer name for #{hostname}: #{inspect(error)}"}

      error ->
        {:error, "** unknown error for #{hostname}: #{inspect(error)}"}
    end
  end

  def report(results, opts \\ []) do
    opts = List.wrap(opts)

    case Keyword.get(opts, :csv) do
      true -> to_csv(results)
      _ -> Enum.each(results, fn result -> reportp(result, opts) end)
    end

    results
    |> Enum.frequencies_by(&statsp/1)
    |> Enum.map(fn {k, v} -> "#{k}: #{v}" end)
    |> Enum.sort()
    |> Enum.join(", ")
    |> Logger.info()
  end

  # results is a list: [{arg, {:ok, result}}, .., {arg, {:error, reason}}, ..]
  defp to_csv(results) do
    {:ok, now} = DateTime.now("Etc/UTC")
    IO.puts("arg,ip,port,idx,tlsv,subject,issuer,not_before,not_after,expiry,alt_names")

    # process the positive results for csv
    for {arg, {:ok, {ip, port, tlsv, certs}}} <- results do
      certs
      |> Enum.with_index()
      |> Enum.map(fn {c, idx} ->
        IO.puts(
          "#{arg},#{ip},#{port},#{idx},#{tlsv},#{c.subject},#{c.issuer},#{c.not_before},#{c.not_after},#{expiry(c, now)},#{c.alt_names}"
        )
      end)
    end

    # log the errors
    for {arg, {:ok, {:error, reason}}} <- results,
        do: Logger.warn("[#{arg}] - #{reason}")
  end

  defp expiry(cert, now) do
    with {:ok, not_after, _} <- DateTime.from_iso8601(cert.not_after) do
      DateTime.diff(not_after, now, :second)
      |> then(fn s -> round(s / 24 / 3600) end)
    else
      _ -> 0
    end
  end

  # Implementation

  defp statsp({_arg, result}) do
    case result do
      {:ok, {:error, _}} -> :error
      {:ok, _} -> :ok
      {:exit, :timeout} -> :timeout
      _ -> :huh
    end
  end

  defp reportp({arg, {:ok, {:error, reason}}}, _opts),
    do: Logger.info("[#{inspect(arg)}] - #{inspect(reason)}")

  defp reportp({arg, {:error, reason}}, _opts),
    do: Logger.info("[#{inspect(arg)}] -> #{inspect(reason)}")

  defp reportp({arg, {:exit, reason}}, _opts),
    do: Logger.info("[#{inspect(arg)}] - #{inspect(reason)}")

  defp reportp({arg, {:ok, {ip, port, tlsv, certs}}}, _opts) do
    addr = "#{Pfx.new(ip)}"
    hostname = hd(certs) |> Map.get(:subjectCommonname)

    Logger.info(
      "#{arg}  #{Enum.count(certs)} certs @ #{hostname} #{addr}:#{port}/tcp, using #{tlsv}"
    )

    certs
    |> Enum.with_index()
    |> Enum.map(fn x -> report_cert(arg, x) end)
  end

  defp report_cert(hostname, {cert, idx}) do
    s = cert.subject
    i = cert.issuer
    b = cert.not_before
    a = cert.not_after
    n = cert.alt_names

    Logger.info(
      "#{hostname} [#{idx}] subject #{s}, issuer #{i}, not_before #{b}, not_after #{a}, alt_names: #{n}"
    )
  end

  @spec expand(String.t()) :: [String.t()]
  defp expand(arg) do
    # - to a list of IP addresses if it is an IPv4/6 prefix
    # - otherwise simply return the argument
    case Pfx.parse(arg) do
      {:ok, pfx} -> Pfx.hosts(pfx) |> Enum.map(fn x -> "#{x}" end)
      {:error, _} -> arg
    end
  end

  defp partial_chain(certs) do
    # certs [Root CA, Intermediates (if any)..., End Certificate]
    # - register chain under fingerprint(End Certificate)
    # - simply always trust the Root CA
    id = :crypto.hash(:sha256, List.last(certs))
    Lx.Register.put(@name, id, certs)
    {:trusted_ca, List.first(certs)}
  end

  defp der_decode(der) do
    {:OTPCertificate, cert, signatureAlgorithm, signature} =
      :public_key.pkix_decode_cert(der, :otp)

    {:OTPTBSCertificate, version, serialNumber, signature2, issuer, validity, subject,
     subjectPublicKeyInfo, issuerID, subjectID, extensions} = cert

    m = %{
      certSignatureAlgo: decode(signatureAlgorithm),
      certSignature: signature,
      version: decode(version),
      serialNumber: serialNumber,
      signature: decode(signature2),
      subjectPublicKeyInfo: decode(subjectPublicKeyInfo),
      issuerID: decode(issuerID),
      subjectID: decode(subjectID)
    }

    m =
      decode(issuer)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("issuer" <> String.capitalize(k)), v)
      end)

    m =
      decode(subject)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("subject" <> String.capitalize(k)), v)
      end)

    m =
      extensions
      |> Enum.map(fn x -> decode(x) end)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("_#{k}"), v)
      end)

    {:Validity, not_before, not_after} = decode(validity)

    m
    |> Map.put(:not_before, not_before)
    |> Map.put(:not_after, not_after)
    |> simplify()
  end

  # keep only the stuff we're interested in (which may change over time)
  # and simplify the keys a bit.
  defp simplify(map) do
    map
    |> Map.take([:not_before, :not_after])
    |> Map.put(:subject, map.subjectCommonname)
    |> Map.put(:issuer, map.issuerCommonname)
    |> Map.put(:alt_names, Map.get(map, :_subjectAltName, []) |> Enum.join("|"))
  end

  # oid_name
  defp oid_name(oid) when is_tuple(oid) do
    case @oids[oid] do
      nil -> Tuple.to_list(oid) |> Enum.join(".") |> (&"unknown OID #{&1}").()
      name -> String.split("#{name}", "-") |> List.last()
    end
  end

  # DECODE values -------------------------------------------------------
  defp decode(nil), do: nil
  defp decode("false"), do: false
  defp decode("true"), do: true
  defp decode(:asn1_NOVALUE), do: :asn1_NOVALUE
  defp decode(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp decode(<<len, str::binary>>) when len == byte_size(str), do: str

  defp decode(bin) when is_binary(bin) do
    case :asn1rt_nif.decode_ber_tlv(bin) do
      {{6, oid}, _x} -> @oids[oid]
      {{12, str}, _x} -> str
      {{19, str}, _x} -> str
      _ -> String.trim(bin)
    end
  end

  # Decode Tuples
  # See https://github.com/voltone/x509/blob/v0.8.2/lib/x509/rdn_sequence.ex#L280
  defp decode({:AttributeTypeAndValue, oid, val}), do: {oid_name(oid), decode(val)}
  defp decode({:OTPSubjectPublicKeyInfo, algo, key}), do: {decode(algo), key}
  defp decode({:SignatureAlgorithm, oid, val}), do: {:SignatureAlgorithm, oid_name(oid), val}
  defp decode({:Validity, start, stop}), do: {:Validity, decode(start), decode(stop)}
  defp decode({:rdnSequence, list}), do: List.flatten(list) |> Enum.map(fn x -> decode(x) end)

  defp decode({:PublicKeyAlgorithm, oid, _x}), do: oid_name(oid)
  defp decode({:Extension, oid, critical, value}), do: decode_ext(@oids[oid], critical, value)
  defp decode({:AccessDescription, oid, uri}), do: {oid_name(oid), decode(uri)}
  defp decode({:DistributionPoint, name, _reason, _issuer}), do: decode(name)
  # def decode({:PolicyInformation, oid, value}), do: {oid_name(oid), decode(value)}
  defp decode({:PolicyQualifierInfo, oid, octets}), do: {oid_name(oid), octets}

  # fullName = GeneralNames
  # `-> https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L128
  # TODO: otherName, x400Address, directoryName, ediPartyName, iPAddress, registeredID
  defp decode({:fullName, value}), do: for({k, v} <- value, do: decode({k, v}))
  defp decode({:rfc822Name, list}), do: List.to_string(list)
  defp decode({:dNSName, list}), do: List.to_string(list)

  # Decode String Values
  defp decode({:utf8String, str}), do: str
  defp decode({:printableString, list}), do: List.to_string(list)
  defp decode({:ia5String, list}), do: List.to_string(list)
  defp decode({:teletexString, list}), do: List.to_string(list)
  defp decode({:uniformResourceIdentifier, list}), do: List.to_string(list)

  # catch all for a single value
  defp decode(value) when is_list(value), do: List.to_string(value)

  # Decode Time for Internet X.509 PKI Certificate and CRL Profile
  # `-> https://tools.ietf.org/html/rfc5280#section-4.1.2.5
  # UTCTime values for X509 ->   YYMMDDHHMMSSZ  nb: YY >= 50: 19YY, else 20YY
  # GenTime values for X509 -> YYYYMMDDHHMMSSZ
  defp decode({:utcTime, [y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}) do
    {y1, y2} = if (y3 - ?0) * 10 + (y4 - ?0) < 50, do: {?2, ?0}, else: {?1, ?9}

    decode({:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]})
  end

  defp decode({:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}) do
    <<y1, y2, y3, y4, ?-, m1, m2, ?-, d1, d2, ?T, h1, h2, ?:, min1, min2, ?:, s1, s2, ?Z>>
  end

  defp decode({:utcTime, val}), do: to_string(val) <> " ?"
  defp decode({:generalTime, val}), do: to_string(val) <> " ?"

  # Decode Extensions (some of them anyway)
  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L124
  # try out 145.45.0.114, that uses :otherName
  # see http://oid-info.com/get/1.3.6.1.4.1.311.20.2.3
  # http://oid-info.com/get/1.3.6.1.4.1.311.20.2.3

  # OID = 1.3.6.1.4.1.311.20.2.3.
  # Internal Name: szOID_NT_PRINCIPAL_NAME.
  # Description: Used to encode the user principal name (UPN) as OtherName in a
  # subject alternative name (SAN) extension, as specified in [RFC3280] section
  # 4.2.1.7.
  # See https://www.quovadisglobal.com/wp-content/uploads/2020/09/QV_PKIo_CPS-v1.4_final-1.pdf
  # search for the 2.16.528.1.1003.1.3.5.2.
  defp decode_ext(:"id-ce-subjectAltName", _critical, value) do
    altnames = for {:dNSName, v} <- value, do: to_string(v)
    {:subjectAltName, altnames}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L225
  defp decode_ext(:"id-ce-extKeyUsage", _critical, value) do
    usage = Enum.map(value, fn oid -> oid_name(oid) end)
    {:extKeyUsage, usage}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L28
  defp decode_ext(:"id-ce-authorityKeyIdentifier", critical, value) do
    [atom | rest] = Tuple.to_list(value)
    {atom, [critical | rest]}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L259
  defp decode_ext(:"id-pe-authorityInfoAccess", _critical, value) do
    list = for accessdesc <- value, do: decode(accessdesc)
    {:authorityInfoAccess, list}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L199
  defp decode_ext(:"id-ce-cRLDistributionPoints", _criticial, list) do
    # not sure if r(eason) and c(rlIssuer) are ever not asn1_NOVALUE
    distripoints = for {:DistributionPoint, dp, r, c} <- list, do: {decode(dp), r, c}
    {:cRLDistributionPoints, distripoints}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L71
  defp decode_ext(:"id-ce-certificatePolicies", _ciritical, value) do
    policies =
      value
      |> Enum.map(fn {:PolicyInformation, oid, val} -> {oid_name(oid), val} end)
      |> Enum.map(fn {name, val} ->
        {name, Enum.map(List.wrap(val), fn x -> decode(x) end)}
      end)

    {:certificatePolicies, policies}
  end

  # raw collection of non-decoded extensions
  defp decode_ext(atom, _critical, value) when is_atom(atom) do
    atom = String.split("#{atom}", "-") |> List.last() |> String.to_atom()
    {atom, value}
  end
end
