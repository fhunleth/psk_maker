defmodule PskMakerTest do
  use ExUnit.Case
  doctest PskMaker

  test "returns error on bad passwords" do
    assert PskMaker.to_psk(
             "SSID",
             "1234567890123456789012345678901234567890123456789012345678901234"
           ) == {:error, :password_too_long}

    assert PskMaker.to_psk("SSID", <<1, 2, 3>>) == {:error, :invalid_characters}
  end

  test "returns error on bad SSIDs" do
    assert PskMaker.to_psk("12345678901234567890123456789012345", "password")
  end

  test "passes IEEE 802.11i test vectors" do
    # See IEEE Std 802.11i-2004 Appendix H.4
    assert PskMaker.to_psk("IEEE", "password") ==
             {:ok,
              <<0xF42C6FC52DF0EBEF9EBB4B90B38A5F90::integer-128,
                0x2E83FE1B135A70E23AED762E9710A12E::integer-128>>}

    assert PskMaker.to_psk("ThisIsASSID", "ThisIsAPassword") ==
             {:ok,
              <<0x0DC0D6EB90555ED6419756B9A15EC3E3::integer-128,
                0x209B63DF707DD508D14581F8982721AF::integer-128>>}

    assert PskMaker.to_psk("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
             {:ok,
              <<0xBECB93866BB8C3832CB777C2F559807C::integer-128,
                0x8C59AFCB6EAE734885001300A981CC62::integer-128>>}
  end
end
