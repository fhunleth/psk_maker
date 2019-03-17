defmodule PskMaker do
  @moduledoc """
  Documentation for PskMaker.
  """

  @typedoc "A WPA2 PSK"
  @type psk :: <<_::256>>

  @doc """
  Convert a WiFi WPA2 passphrase into a PSK

  This implements the algorithm in IEEE Std 802.11i-2004 Appendix H.4.
  """
  @spec to_psk(String.t(), String.t()) :: {:ok, psk()} | {:error, atom()}
  def to_psk(ssid, password) do
    with :ok <- password_ok(password),
         :ok <- ssid_ok(ssid) do
      result = f(ssid, password, 4096, 1) <> f(ssid, password, 4096, 2)
      <<result256::binary-size(32), _::binary>> = result
      {:ok, result256}
    end
  end

  # F(P, S, c, i) = U1 xor U2 xor ... Uc
  # U1 = PRF(P, S || Int(i))
  # U2 = PRF(P, U1)
  # Uc = PRF(P, Uc-1)
  defp f(ssid, password, iterations, count) do
    digest = <<ssid::binary, count::integer-32>>
    digest1 = sha1_hmac(digest, password)

    iterate(digest1, digest1, password, iterations - 1)
  end

  defp iterate(acc, _previous_digest, _password, 0) do
    acc
  end

  defp iterate(acc, previous_digest, password, n) do
    digest = sha1_hmac(previous_digest, password)
    iterate(xor160(acc, digest), digest, password, n - 1)
  end

  defp xor160(<<a::160>>, <<b::160>>) do
    <<:erlang.bxor(a, b)::160>>
  end

  defp sha1_hmac(digest, password) do
    :crypto.hmac(:sha, password, digest)
  end

  defp password_ok(password) when byte_size(password) <= 63 do
    all_ascii(password)
  end

  defp password_ok(_password), do: {:error, :password_too_long}

  defp ssid_ok(ssid) when byte_size(ssid) <= 32, do: :ok
  defp ssid_ok(_password), do: {:error, :ssid_too_long}

  defp all_ascii(<<c, rest::binary>>) when c >= 32 and c <= 126 do
    all_ascii(rest)
  end

  defp all_ascii(<<>>), do: :ok

  defp all_ascii(_other), do: {:error, :invalid_characters}
end
