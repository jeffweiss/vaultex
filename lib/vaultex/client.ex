defmodule Vaultex.Client do
  @moduledoc """
  Provides a functionality to authenticate and read from a vault endpoint.
  """

  use GenServer
  alias Vaultex.Auth, as: Auth
  alias Vaultex.Read, as: Read
  alias Vaultex.Write, as: Write
  @version "v1"

  def start_link() do
    GenServer.start_link(__MODULE__, %{progress: "starting"})
  end

  def init(state) do
    {:ok, Map.merge(state, %{url: url()})}
  end

  @doc """
  Authenticates with vault using a tuple. This can be executed before attempting to read secrets from vault.

  ## Parameters

    - method: Auth backend to use for authenticating, can be one of `:approle, :app_id, :userpass, :github`
    - credentials: A tuple used for authentication depending on the method, `{role_id, secret_id}` for :approle, `{app_id, user_id}` for `:app_id`, `{username, password}` for `:userpass`, `{github_token}` for `:github`

  ## Examples

    ```
    iex> Vaultex.Client.auth(:app_id, {app_id, user_id})
    {:ok, :authenticated}

    iex> Vaultex.Client.auth(:userpass, {username, password})
    {:error, ["Something didn't work"]}

    iex> Vaultex.Client.auth(:github, {github_token})
    {:ok, :authenticated}
    ```
  """
  def auth(pid, method, credentials) do
    GenServer.call(pid, {:auth, method, credentials})
  end

  @doc """
  Reads a secret from vault given a path.

  ## Parameters

    - key: A String path to be used for querying vault.
    - auth_method and credentials: See Vaultex.Client.auth

  ## Examples

    ```
    iex> Vaultex.Client.read "secret/foo", :app_id, {app_id, user_id}
    {:ok, %{"value" => "bar"}}

    iex> Vaultex.Client.read "secret/baz", :userpass, {username, password}
    {:error, ["Key not found"]}

    iex> Vaultex.Client.read "secret/bar", :github, {github_token}
    {:ok, %{"value" => "bar"}}
    ```

  """
  def read(pid, key, auth_method, credentials) do
    response = read(pid, key)
    case response do
      {:ok, _} -> response
      {:error, _} ->
        with {:ok, _} <- auth(pid, auth_method, credentials),
          do: read(pid, key)
    end
  end

  defp read(pid, key) do
    GenServer.call(pid, {:read, key})
  end

  @doc """
  Writes a secret to Vault given a path.

  ## Parameters

    - key: A String path where the secret will be written.
    - value: A String => String map that will be stored in Vault
    - auth_method and credentials: See Vaultex.Client.auth

  ## Examples

    ```
    iex> Vaultex.Client.write "secret/foo", %{"value" => "bar"}, :app_id, {app_id, user_id}
    :ok
    ```
  """
  def write(pid, key, value, auth_method, credentials) do
    response = write(pid, key, value)
    case response do
      :ok -> response
      {:ok, response} -> {:ok, response}
      {:error, _} ->
        with {:ok, _} <- auth(pid, auth_method, credentials),
          do: write(pid, key, value)
    end
  end

  defp write(pid, key, value) do
    GenServer.call(pid, {:write, key, value})
  end

  def handle_call({:read, key}, _from, state) do
    Read.handle(key, state)
  end

  def handle_call({:write, key, value}, _from, state) do
    Write.handle(key, value, state)
  end

  def handle_call({:auth, method, credentials}, _from, state) do
    Auth.handle(method, credentials, state)
  end

  defp url do
    "#{scheme()}://#{host()}:#{port()}/#{@version}/"
  end

  defp host do
    parsed_vault_addr().host || get_env(:host)
  end

  defp port do
    parsed_vault_addr().port || get_env(:port)
  end

  defp scheme do
    parsed_vault_addr().scheme || get_env(:scheme)
  end

  defp parsed_vault_addr do
    get_env(:vault_addr) |> to_string |> URI.parse
  end

  defp get_env(:host) do
    System.get_env("VAULT_HOST") || Application.get_env(:vaultex, :host) || "localhost"
  end

  defp get_env(:port) do
      System.get_env("VAULT_PORT") || Application.get_env(:vaultex, :port) || 8200
  end

  defp get_env(:scheme) do
      System.get_env("VAULT_SCHEME") || Application.get_env(:vaultex, :scheme) || "http"
  end

  defp get_env(:vault_addr) do
    System.get_env("VAULT_ADDR") || Application.get_env(:vaultex, :vault_addr)
  end
end
