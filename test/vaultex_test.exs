defmodule VaultexTest do
  use ExUnit.Case
  doctest Vaultex

  setup do
    {:ok, pid} = Vaultex.Client.start_link()
    %{pid: pid}
  end

  test "Authentication of role_id and secret_id is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :approle, {"good", "whatever"}) == {:ok, :authenticated}
  end

  test "Authentication of role_id and secret_id is unsuccessful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :approle, {"bad", "whatever"}) == {:error, ["Not Authenticated"]}
  end

  test "Authentication of app_id and user_id is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :app_id, {"good", "whatever"}) == {:ok, :authenticated}
  end

  test "Authentication of app_id and user_id is unsuccessful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :app_id, {"bad", "whatever"}) == {:error, ["Not Authenticated"]}
  end

  test "Authentication of app_id and user_id requiring redirects is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :app_id, {"redirects_good", "whatever"}) == {:ok, :authenticated}
  end

  test "Authentication of app_id and user_id causes an exception", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :app_id, {"boom", "whatever"}) == {:error, ["Bad response from vault [http://localhost:8200/v1/]", "econnrefused"]}
  end

  test "Authentication of userpass is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :userpass, {"user", "good"}) == {:ok, :authenticated}
  end

  test "Authentication of userpass requiring redirects is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :userpass, {"user", "redirects_good"}) == {:ok, :authenticated}
  end

  test "Authentication of userpass is unsuccessful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :userpass, {"user", "bad"}) == {:error, ["Not Authenticated"]}
  end

  test "Authentication of userpass causes an exception", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :userpass, {"user", "boom"}) == {:error, ["Bad response from vault [http://localhost:8200/v1/]", "econnrefused"]}
  end

  test "Authentication of github_token is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :github, {"good"}) == {:ok, :authenticated}
  end

  test "Authentication of github_token is unsuccessful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :github, {"bad"}) == {:error, ["Not Authenticated"]}
  end

  test "Authentication of github_token requiring redirects is successful", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :github, {"redirects_good"}) == {:ok, :authenticated}
  end

  test "Authentication of github_token causes an exception", %{pid: pid} do
    assert Vaultex.Client.auth(pid, :github, {"boom"}) == {:error, ["Bad response from vault [http://localhost:8200/v1/]", "econnrefused"]}
  end

  test "Read of valid secret key returns the correct value", %{pid: pid} do
    assert Vaultex.Client.read(pid, "secret/foo", :app_id, {"good", "whatever"}) == {:ok, %{"value" => "bar"}}
  end

  test "Read of valid secret key requiring redirect returns the correct value", %{pid: pid} do
    assert Vaultex.Client.read(pid, "secret/foo/redirects", :app_id, {"good", "whatever"}) == {:ok, %{"value" => "bar"}}
  end

  test "Read of non existing secret key returns error", %{pid: pid} do
    assert Vaultex.Client.read(pid, "secret/baz", :app_id, {"good", "whatever"}) == {:error, ["Key not found"]}
  end

  test "Read of a secret key given bad authentication returns error", %{pid: pid} do
    assert Vaultex.Client.read(pid, "secret/faz", :app_id, {"bad", "whatever"}) == {:error, ["Not Authenticated"]}
  end

  test "Read of a secret key causes and exception", %{pid: pid} do
    assert Vaultex.Client.read(pid, "secret/boom", :app_id, {"good", "whatever"}) == {:error, ["Bad response from vault [http://localhost:8200/v1/]", "econnrefused"]}
  end

  test "Write of valid secret key returns :ok", %{pid: pid} do
    assert Vaultex.Client.write(pid, "secret/foo", %{"value" => "bar"}, :app_id, {"good", "whatever"}) == :ok
  end

  test "Write of valid secret key requiring redirect returns :ok", %{pid: pid} do
    assert Vaultex.Client.write(pid, "secret/foo/redirects", %{"value" => "bar"}, :app_id, {"good", "whatever"}) == :ok
  end

  test "Write of valid secret key requiring response returns :ok and response", %{pid: pid} do
    assert Vaultex.Client.write(pid, "secret/foo/withresponse", %{"value" => "bar"}, :app_id, {"good", "whatever"}) == {:ok, %{"value" => "bar"}}
  end

end
