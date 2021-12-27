from __future__ import annotations
import unittest
import configparser
import time
from datetime import datetime
import uuid
from src.austin_heller_repo.client_authentication_manager import ClientAuthenticationClientServerMessage, OpenidAuthenticationRequestClientServerMessage, OpenidAuthenticationConfiguration, ClientAuthenticationManagerStructureFactory, OpenidConnectRedirectHttpServer, AuthenticationResponseClientServerMessage
from austin_heller_repo.socket_queued_message_framework import ServerMessengerFactory, ClientMessengerFactory
from austin_heller_repo.socket import ServerSocketFactory, ClientSocketFactory
from austin_heller_repo.threading import SingletonMemorySequentialQueueFactory, Semaphore, start_thread
from austin_heller_repo.common import HostPointer


def get_default_openid_authentication_configuration() -> OpenidAuthenticationConfiguration:
	config = configparser.ConfigParser()
	config.read("./oauth_settings.ini")

	google_config = config["Google"]
	authentication_url = google_config["AuthorizationUrl"]
	token_url = google_config["TokenUrl"]
	scope = google_config["Scope"].split(",")
	redirect_url = google_config["RedirectUrl"]
	redirect_port = google_config["RedirectPort"]
	jwt_pubkey_url = google_config["JwtPubKeyUrl"]
	expected_issuer_url = google_config["ExpectedIssuerUrl"]
	algorithm = google_config["Algorithm"]

	config.read("./client_settings.ini")
	client_credentials_config = config["ClientCredentials"]
	client_id = client_credentials_config["ClientId"]
	client_secret = client_credentials_config["ClientSecret"]

	return OpenidAuthenticationConfiguration(
		client_id=client_id,
		client_secret=client_secret,
		authentication_url=authentication_url,
		token_url=token_url,
		scope=scope,
		redirect_url=redirect_url,
		redirect_port=redirect_port,
		jwt_pubkey_url=jwt_pubkey_url,
		expected_issuer_url=expected_issuer_url,
		algorithm=algorithm
	)


def get_default_http_server_port() -> int:
	config = configparser.ConfigParser()
	config.read("./oauth_settings.ini")
	oauth_config = config["Google"]
	return int(oauth_config["RedirectPort"])


def get_default_server_messenger_factory() -> ServerMessengerFactory:
	return ServerMessengerFactory(
		server_socket_factory=ServerSocketFactory(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=1.0
		),
		sequential_queue_factory=SingletonMemorySequentialQueueFactory(),
		local_host_pointer=HostPointer(
			host_address="localhost",
			host_port=35461
		),
		client_server_message_class=ClientAuthenticationClientServerMessage,
		structure_factory=ClientAuthenticationManagerStructureFactory(
			openid_authentication_configuration=get_default_openid_authentication_configuration()
		)
	)


def get_default_client_messenger_factory() -> ClientMessengerFactory:
	return ClientMessengerFactory(
		client_socket_factory=ClientSocketFactory(
			to_server_packet_bytes_length=4096
		),
		server_host_pointer=HostPointer(
			host_address="localhost",
			host_port=35461
		),
		client_server_message_class=ClientAuthenticationClientServerMessage
	)


class ClientAuthenticationManagerTest(unittest.TestCase):

	def test_initialize(self):

		server_messenger = get_default_server_messenger_factory().get_server_messenger()

		self.assertIsNotNone(server_messenger)

		client_messenger = get_default_client_messenger_factory().get_client_messenger()

		self.assertIsNotNone(client_messenger)

	def test_connect(self):

		server_messenger = get_default_server_messenger_factory().get_server_messenger()

		server_messenger.start_receiving_from_clients()

		time.sleep(1)

		client_messenger = get_default_client_messenger_factory().get_client_messenger()

		client_messenger.connect_to_server()

		time.sleep(1)

		server_messenger.stop_receiving_from_clients()

		time.sleep(1)

		client_messenger.dispose()

		time.sleep(1)

	def test_request_authentication(self):

		server_messenger = get_default_server_messenger_factory().get_server_messenger()

		server_messenger.start_receiving_from_clients()

		time.sleep(1)

		client_messenger = get_default_client_messenger_factory().get_client_messenger()

		client_messenger.connect_to_server()

		time.sleep(1)

		# start the HTTP Server

		http_server = None  # type: OpenidConnectRedirectHttpServer

		def http_server_thread_method():
			nonlocal http_server

			try:
				print(f"{datetime.utcnow()}: test: http_server_thread_method: start")

				http_server = OpenidConnectRedirectHttpServer(
					listen_port=get_default_http_server_port(),
					client_authentication_manager_client_messenger_factory=get_default_client_messenger_factory()
				)
				print(f"{datetime.utcnow()}: test: http_server_thread_method: http_server.start()")
				http_server.start()
			except Exception as ex:
				print(f"{datetime.utcnow()}: test: http_server_thread_method: ex: {ex}")
			finally:
				print(f"{datetime.utcnow()}: test: http_server_thread_method: end")

		http_server_thread = start_thread(http_server_thread_method)

		time.sleep(1)

		# send the authentication request message

		callback_total = 0

		def callback(client_server_message: ClientAuthenticationClientServerMessage):
			nonlocal callback_total
			callback_total += 1
			print(f"{datetime.utcnow()}: test: callback: client_server_message: {client_server_message.__class__.get_client_server_message_type()}")
			self.assertIsInstance(client_server_message, AuthenticationResponseClientServerMessage)

		found_exception = None

		def on_exception(exception: Exception):
			nonlocal found_exception
			if found_exception is None:
				found_exception = exception

		client_messenger.receive_from_server(
			callback=callback,
			on_exception=on_exception
		)

		client_messenger.send_to_server(
			request_client_server_message=OpenidAuthenticationRequestClientServerMessage()
		)

		# wait for authentication response message

		print(f"{datetime.utcnow()}: test: waiting for response so APPROVE ACCESS NOW")

		time.sleep(5)

		print(f"{datetime.utcnow()}: test: client_messenger.dispose()")

		client_messenger.dispose()

		time.sleep(1)

		print(f"{datetime.utcnow()}: test: server_messenger.stop_receiving_from_clients()")

		server_messenger.stop_receiving_from_clients()

		time.sleep(1)

		print(f"{datetime.utcnow()}: test: http_server.stop()")

		http_server.stop()

		time.sleep(1)

		print(f"{datetime.utcnow()}: test: http_server_thread.join()")

		http_server_thread.join()

		print(f"{datetime.utcnow()}: test: HTTP server thread: stopped")

		if found_exception is not None:
			raise found_exception

		self.assertEqual(1, callback_total)
