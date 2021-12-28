from __future__ import annotations
from typing import List, Tuple, Dict, Callable, Type, Set
import os
import tempfile
import time
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from austin_heller_repo.threading import Semaphore
from austin_heller_repo.socket_queued_message_framework import Structure, StructureStateEnum, ClientServerMessageTypeEnum, ClientServerMessage, StructureInfluence, StructureTransitionException, ClientMessengerFactory, ServerMessengerFactory, ClientMessenger, ServerMessenger, StructureFactory
from jose import jwt
import requests
from requests_oauthlib import OAuth2Session
import uuid
import http.server
import webbrowser


class ClientAuthenticationStructureStateEnum(StructureStateEnum):
	ClientUnauthenticated = "client_unauthenticated"
	ClientWaitingForResponse = "client_waiting_for_response"
	ClientAuthenticationSuccessful = "client_authentication_successful"
	ClientAuthenticationFailure = "client_authentication_failure"


class ClientAuthenticationClientServerMessageTypeEnum(ClientServerMessageTypeEnum):
	OpenidAuthenticationRequest = "openid_authentication_request"
	UrlNavigationNeededResponse = "url_navigation_needed_response"
	OpenidAuthenticationResponse = "openid_authentication_response"
	AuthenticationResponse = "authentication_response"
	UnexpectedAuthenticationRequest = "unexpected_authentication_request"


class ClientAuthenticationManagerStructureStateEnum(StructureStateEnum):
	Active = "active"


class ClientAuthenticationClientServerMessage(ClientServerMessage):

	def __init__(self):
		super().__init__()

		pass

	@classmethod
	def get_client_server_message_type_class(cls) -> Type[ClientServerMessageTypeEnum]:
		return ClientAuthenticationClientServerMessageTypeEnum


class OpenidAuthenticationRequestClientServerMessage(ClientAuthenticationClientServerMessage):

	def __init__(self):
		super().__init__()

		pass

	@classmethod
	def get_client_server_message_type(cls) -> ClientServerMessageTypeEnum:
		return ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationRequest

	def to_json(self) -> Dict:
		json_object = super().to_json()
		return json_object

	def is_response(self) -> bool:
		return False

	def get_destination_uuid(self) -> str:
		return None

	def is_structural_influence(self) -> bool:
		return True

	def is_ordered(self) -> bool:
		return True

	def get_structural_error_client_server_message_response(self, *, structure_transition_exception: StructureTransitionException, destination_uuid: str) -> ClientServerMessage:
		return UnexpectedAuthenticationRequestClientServerMessage(
			structure_state_name=structure_transition_exception.get_structure_state().value,
			client_server_message_json_string=json.dumps(structure_transition_exception.get_structure_influence().get_client_server_message().to_json()),
			destination_uuid=destination_uuid
		)


class UrlNavigationNeededResponseClientServerMessage(ClientAuthenticationClientServerMessage):

	def __init__(self, *, url: str, destination_uuid: str):
		super().__init__()

		self.__url = url
		self.__destination_uuid = destination_uuid

	def get_url(self) -> str:
		return self.__url

	def navigate_to_url(self):
		webbrowser.open(self.__url, new=2)

	@classmethod
	def get_client_server_message_type(cls) -> ClientServerMessageTypeEnum:
		return ClientAuthenticationClientServerMessageTypeEnum.UrlNavigationNeededResponse

	def to_json(self) -> Dict:
		json_object = super().to_json()
		json_object["url"] = self.__url
		json_object["destination_uuid"] = self.__destination_uuid
		return json_object

	def is_response(self) -> bool:
		return True

	def get_destination_uuid(self) -> str:
		return self.__destination_uuid

	def is_structural_influence(self) -> bool:
		return False

	def is_ordered(self) -> bool:
		return True

	def get_structural_error_client_server_message_response(self, *, structure_transition_exception: StructureTransitionException, destination_uuid: str) -> ClientServerMessage:
		return UnexpectedAuthenticationRequestClientServerMessage(
			structure_state_name=structure_transition_exception.get_structure_state().value,
			client_server_message_json_string=json.dumps(structure_transition_exception.get_structure_influence().get_client_server_message().to_json()),
			destination_uuid=destination_uuid
		)


class OpenidAuthenticationResponseClientServerMessage(ClientAuthenticationClientServerMessage):
	# Purpose: to send a response from the HTTP server that an OpenID Connect response was received for a specific client

	def __init__(self, *, state: str, code: str):  # TODO include data specific to the OpenID Connect response
		super().__init__()

		self.__state = state
		self.__code = code

	def get_state(self) -> str:
		return self.__state

	def get_code(self) -> str:
		return self.__code

	@classmethod
	def get_client_server_message_type(cls) -> ClientServerMessageTypeEnum:
		return ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationResponse

	def to_json(self) -> Dict:
		json_object = super().to_json()
		json_object["state"] = self.__state
		json_object["code"] = self.__code
		return json_object

	def is_response(self) -> bool:
		return False

	def get_destination_uuid(self) -> str:
		return None

	def is_structural_influence(self) -> bool:
		return True

	def is_ordered(self) -> bool:
		return True

	def get_structural_error_client_server_message_response(self, *, structure_transition_exception: StructureTransitionException, destination_uuid: str) -> ClientServerMessage:
		return UnexpectedAuthenticationRequestClientServerMessage(
			structure_state_name=structure_transition_exception.get_structure_state().value,
			client_server_message_json_string=json.dumps(structure_transition_exception.get_structure_influence().get_client_server_message().to_json()),
			destination_uuid=destination_uuid
		)


class AuthenticationResponseClientServerMessage(ClientAuthenticationClientServerMessage):

	def __init__(self, *, is_successful: bool, destination_uuid: str, external_client_id: str):
		super().__init__()

		self.__is_successful = is_successful
		self.__destination_uuid = destination_uuid
		self.__external_client_id = external_client_id

	def is_successful(self) -> bool:
		return self.__is_successful

	def get_external_client_id(self) -> str:
		return self.__external_client_id

	@classmethod
	def get_client_server_message_type(cls) -> ClientServerMessageTypeEnum:
		return ClientAuthenticationClientServerMessageTypeEnum.AuthenticationResponse

	def to_json(self) -> Dict:
		json_object = super().to_json()
		json_object["is_successful"] = self.__is_successful
		json_object["destination_uuid"] = self.__destination_uuid
		json_object["external_client_id"] = self.__external_client_id
		return json_object

	def is_response(self) -> bool:
		return True

	def get_destination_uuid(self) -> str:
		return self.__destination_uuid

	def is_structural_influence(self) -> bool:
		return False

	def is_ordered(self) -> bool:
		return True

	def get_structural_error_client_server_message_response(self, *, structure_transition_exception: StructureTransitionException, destination_uuid: str) -> ClientServerMessage:
		return UnexpectedAuthenticationRequestClientServerMessage(
			structure_state_name=structure_transition_exception.get_structure_state().value,
			client_server_message_json_string=json.dumps(structure_transition_exception.get_structure_influence().get_client_server_message().to_json()),
			destination_uuid=destination_uuid
		)


class UnexpectedAuthenticationRequestClientServerMessage(ClientAuthenticationClientServerMessage):

	def __init__(self, *, structure_state_name: str, client_server_message_json_string: str, destination_uuid: str):
		super().__init__()

		self.__structure_state_name = structure_state_name
		self.__client_server_message_json_string = client_server_message_json_string
		self.__destination_uuid = destination_uuid

	def get_structure_state(self) -> ClientAuthenticationStructureStateEnum:
		return ClientAuthenticationStructureStateEnum(self.__structure_state_name)

	def get_client_server_message(self) -> ClientAuthenticationClientServerMessage:
		return ClientAuthenticationClientServerMessage.parse_from_json(
			json_object=json.loads(self.__client_server_message_json_string)
		)

	@classmethod
	def get_client_server_message_type(cls) -> ClientServerMessageTypeEnum:
		return ClientAuthenticationClientServerMessageTypeEnum.UnexpectedAuthenticationRequest

	def to_json(self) -> Dict:
		json_object = super().to_json()
		json_object["structure_state_name"] = self.__structure_state_name
		json_object["client_server_message_json_string"] = self.__client_server_message_json_string
		json_object["destination_uuid"] = self.__destination_uuid
		return json_object

	def is_response(self) -> bool:
		return True

	def get_destination_uuid(self) -> str:
		return self.__destination_uuid

	def is_structural_influence(self) -> bool:
		return False

	def is_ordered(self) -> bool:
		return True

	def get_structural_error_client_server_message_response(self, *, structure_transition_exception: StructureTransitionException, destination_uuid: str) -> ClientServerMessage:
		return None


class OpenidAuthenticationConfiguration():

	def __init__(self, *, client_id: str, client_secret: str, authentication_url: str, token_url: str, scope: List[str], redirect_url: str, redirect_port: int, jwt_pubkey_url: str, expected_issuer_url: str, algorithm: str):

		self.__client_id = client_id
		self.__client_secret = client_secret
		self.__authentication_url = authentication_url
		self.__token_url = token_url
		self.__scope = scope
		self.__redirect_url = redirect_url
		self.__redirect_port = redirect_port
		self.__expected_issuer_url = expected_issuer_url
		self.__jwt_pubkey_url = jwt_pubkey_url
		self.__algorithm = algorithm

	def get_client_id(self) -> str:
		return self.__client_id

	def get_client_secret(self) -> str:
		return self.__client_secret

	def get_authentication_url(self) -> str:
		return self.__authentication_url

	def get_token_url(self) -> str:
		return self.__token_url

	def get_scope(self) -> List[str]:
		return self.__scope

	def get_redirect_url(self) -> str:
		return self.__redirect_url

	def get_redirect_port(self) -> int:
		return self.__redirect_port

	def get_expected_issuer_url(self) -> str:
		return self.__expected_issuer_url

	def get_jwt_pubkey_url(self) -> str:
		return self.__jwt_pubkey_url

	def get_algorithm(self) -> str:
		return self.__algorithm


def get_openid_connect_http_request_handler(*, client_authentication_manager_client_messenger_factory: ClientMessengerFactory, authenticated_bytes: bytes, favicon_bytes: bytes):
	class OpenidConnectHttpRequestHandler(http.server.BaseHTTPRequestHandler):

		__states_sent_via_client_messenger = set()  # type: Set[str]
		__states_sent_via_client_messenger_semaphore = Semaphore()

		def __init__(self, request, client_address, server):
			super().__init__(request, client_address, server)

			self.__request = request
			self.__client_address = client_address
			self.__server = server

		def do_GET(self):
			print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: start")
			print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: self.path: {self.path}")
			print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: self.request: {self.request}")
			client_authentication_manager_client_messenger = client_authentication_manager_client_messenger_factory.get_client_messenger()
			try:
				if self.path == "/favicon.ico":
					self.send_response(200)
					self.send_header("Content-Length", str(len(favicon_bytes)))
					self.end_headers()
					self.wfile.write(favicon_bytes)
				else:
					url_query = urlparse(self.path).query
					url_query_dict = parse_qs(url_query)
					state = url_query_dict["state"][0]
					print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: state: {state}")

					OpenidConnectHttpRequestHandler.__states_sent_via_client_messenger_semaphore.acquire()
					if state not in OpenidConnectHttpRequestHandler.__states_sent_via_client_messenger:
						print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: adding state")
						OpenidConnectHttpRequestHandler.__states_sent_via_client_messenger.add(state)
						is_send_via_client_messenger_required = True
					else:
						print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: already processed state")
						is_send_via_client_messenger_required = False
					OpenidConnectHttpRequestHandler.__states_sent_via_client_messenger_semaphore.release()
					if is_send_via_client_messenger_required:
						code = url_query_dict["code"][0]
						print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: connecting to server")
						client_authentication_manager_client_messenger.connect_to_server()
						print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: sending to server")
						client_authentication_manager_client_messenger.send_to_server(
							request_client_server_message=OpenidAuthenticationResponseClientServerMessage(
								state=state,
								code=code
							)
						)
					self.send_response(200)
					self.send_header("Content-Length", str(len(authenticated_bytes)))
					self.end_headers()
					self.wfile.write(authenticated_bytes)
			finally:
				print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: disposing client messenger")
				client_authentication_manager_client_messenger.dispose()
			print(f"{datetime.utcnow()}: OpenidConnectHttpRequestHandler: do_GET: end")
	return OpenidConnectHttpRequestHandler


class OpenidConnectRedirectHttpServer():

	def __init__(self, *, listen_port: int, client_authentication_manager_client_messenger_factory: ClientMessengerFactory, authenticated_html_file_path: str, favicon_file_path: str):

		self.__listen_port = listen_port
		self.__client_authentication_manager_client_messenger_factory = client_authentication_manager_client_messenger_factory
		self.__authenticated_html_file_path = authenticated_html_file_path
		self.__favicon_file_path = favicon_file_path

		self.__http_server = None  # type: http.server.HTTPServer

	def start(self):

		with open(self.__authenticated_html_file_path, "rb") as file_handle:
			authenticated_bytes = file_handle.read()
		with open(self.__favicon_file_path, "rb") as file_handle:
			favicon_bytes = file_handle.read()

		self.__http_server = http.server.HTTPServer(
			server_address=('', self.__listen_port),
			RequestHandlerClass=get_openid_connect_http_request_handler(
				client_authentication_manager_client_messenger_factory=self.__client_authentication_manager_client_messenger_factory,
				authenticated_bytes=authenticated_bytes,
				favicon_bytes=favicon_bytes
			)
		)
		self.__http_server.serve_forever()

	def stop(self):

		self.__http_server.shutdown()
		self.__http_server.server_close()


class ClientAuthenticationStructure(Structure):

	def __init__(self, *, openid_authentication_configuration: OpenidAuthenticationConfiguration, client_uuid: str):
		super().__init__(
			states=ClientAuthenticationStructureStateEnum,
			initial_state=ClientAuthenticationStructureStateEnum.ClientUnauthenticated
		)

		self.__openid_authentication_configuration = openid_authentication_configuration
		self.__client_uuid = client_uuid

		self.__expected_response_nonce = None  # type: str
		self.__oauth2_state = None  # type: str
		self.__access_token = None  # type: str

		self.add_transition(
			client_server_message_type=ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationRequest,
			start_structure_state=ClientAuthenticationStructureStateEnum.ClientUnauthenticated,
			end_structure_state=ClientAuthenticationStructureStateEnum.ClientWaitingForResponse,
			on_transition=self.__client_authentication_requested
		)

		self.add_transition(
			client_server_message_type=ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationResponse,
			start_structure_state=ClientAuthenticationStructureStateEnum.ClientWaitingForResponse,
			end_structure_state=ClientAuthenticationStructureStateEnum.ClientWaitingForResponse,
			on_transition=self.__client_authentication_response_received
		)

	def get_oauth2_state(self) -> str:
		return self.__oauth2_state

	# TODO set the state from ClientWaitingForResponse back to ClientUnauthenticated if timeout

	def __client_authentication_requested(self, structure_influence: StructureInfluence):
		self.__expected_response_nonce = str(uuid.uuid4())

		provider = OAuth2Session(
			client_id=self.__openid_authentication_configuration.get_client_id(),
			scope=self.__openid_authentication_configuration.get_scope(),
			redirect_uri=self.__openid_authentication_configuration.get_redirect_url()
		)
		try:
			oauth2_url, oauth2_state = provider.authorization_url(
				url=self.__openid_authentication_configuration.get_authentication_url(),
				nonce=self.__expected_response_nonce
			)
			self.__oauth2_state = oauth2_state

			# the HTTP server should be up and running already to receive redirect responses

			self.send_response(
				client_server_message=UrlNavigationNeededResponseClientServerMessage(
					url=oauth2_url,
					destination_uuid=self.__client_uuid
				)
			)
		finally:
			provider.close()

	def __client_authentication_response_received(self, structure_influence: StructureInfluence):
		openid_authentication_response = structure_influence.get_client_server_message()  # type: OpenidAuthenticationResponseClientServerMessage
		oauth2_state = openid_authentication_response.get_state()
		if oauth2_state == self.__oauth2_state:
			print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: Found oauth2_state")

			provider = OAuth2Session(
				client_id=self.__openid_authentication_configuration.get_client_id(),
				redirect_uri=self.__openid_authentication_configuration.get_redirect_url(),
				state=self.__oauth2_state
			)

			try:
				fetch_token_response = provider.fetch_token(
					token_url=self.__openid_authentication_configuration.get_token_url(),
					code=openid_authentication_response.get_code(),
					client_secret=self.__openid_authentication_configuration.get_client_secret()
				)

				print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: fetch_token_response: {fetch_token_response}")

				self.__access_token = fetch_token_response["access_token"]

				jwt_pubkeys = requests.get(self.__openid_authentication_configuration.get_jwt_pubkey_url()).json()

				print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: jwt_pubkeys: {jwt_pubkeys}")

				print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: get_algorithm: {self.__openid_authentication_configuration.get_algorithm()}")

				claims = jwt.decode(
					token=fetch_token_response["id_token"],
					key=jwt_pubkeys,
					issuer=self.__openid_authentication_configuration.get_expected_issuer_url(),
					audience=self.__openid_authentication_configuration.get_client_id(),
					algorithms=[self.__openid_authentication_configuration.get_algorithm()],
					access_token=self.__access_token
				)

				if claims["nonce"] == self.__expected_response_nonce:
					print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: Found nonce")
					print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: Google user ID: {claims['sub']}")
					self.set_state(
						structure_state=ClientAuthenticationStructureStateEnum.ClientAuthenticationSuccessful
					)
					self.send_response(
						client_server_message=AuthenticationResponseClientServerMessage(
							is_successful=True,
							destination_uuid=self.__client_uuid,
							external_client_id=claims["sub"]
						)
					)
				else:
					print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: Nonce mismatch: Actual: {claims['nonce']} != Expected: {self.__expected_response_nonce}")
					self.set_state(
						structure_state=ClientAuthenticationStructureStateEnum.ClientAuthenticationFailure
					)
			finally:
				provider.close()
		else:
			print(f"{datetime.utcnow()}: ClientAuthenticationStructure: __client_authentication_response_received: state mismatch: Actual {oauth2_state} != Expected {self.__oauth2_state}.")


class ClientAuthenticationManagerStructure(Structure):

	def __init__(self, *, openid_authentication_configuration: OpenidAuthenticationConfiguration):
		super().__init__(
			states=ClientAuthenticationManagerStructureStateEnum,
			initial_state=ClientAuthenticationManagerStructureStateEnum.Active
		)

		self.__openid_authentication_configuration = openid_authentication_configuration

		self.__client_authentication_structure_per_client_uuid = {}  # type: Dict[str, ClientAuthenticationStructure]
		self.__client_authentication_structure_per_client_uuid_semphore = Semaphore()

		self.add_transition(
			client_server_message_type=ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationRequest,
			start_structure_state=ClientAuthenticationManagerStructureStateEnum.Active,
			end_structure_state=ClientAuthenticationManagerStructureStateEnum.Active,
			on_transition=self.__openid_authentication_requested
		)

		self.add_transition(
			client_server_message_type=ClientAuthenticationClientServerMessageTypeEnum.OpenidAuthenticationResponse,
			start_structure_state=ClientAuthenticationManagerStructureStateEnum.Active,
			end_structure_state=ClientAuthenticationManagerStructureStateEnum.Active,
			on_transition=self.__openid_authentication_response_received
		)

	def __openid_authentication_requested(self, structure_influence: StructureInfluence):
		openid_authentication_request = structure_influence.get_client_server_message()  # type: OpenidAuthenticationRequestClientServerMessage
		client_uuid = structure_influence.get_source_uuid()
		self.__client_authentication_structure_per_client_uuid_semphore.acquire()
		if client_uuid not in self.__client_authentication_structure_per_client_uuid:
			client_authentication_structure = ClientAuthenticationStructure(
				openid_authentication_configuration=self.__openid_authentication_configuration,
				client_uuid=client_uuid
			)
			self.register_child_structure(
				structure=client_authentication_structure
			)
			self.__client_authentication_structure_per_client_uuid[client_uuid] = client_authentication_structure
		self.__client_authentication_structure_per_client_uuid_semphore.release()
		self.__client_authentication_structure_per_client_uuid[client_uuid].update_structure(
			structure_influence=structure_influence
		)

	def __openid_authentication_response_received(self, structure_influence: StructureInfluence):
		openid_authentication_response = structure_influence.get_client_server_message()  # type: OpenidAuthenticationResponseClientServerMessage
		self.__client_authentication_structure_per_client_uuid_semphore.acquire()
		for client_uuid in self.__client_authentication_structure_per_client_uuid.keys():
			client_authentication_structure = self.__client_authentication_structure_per_client_uuid[client_uuid]
			if client_authentication_structure.get_oauth2_state() == openid_authentication_response.get_state():
				client_authentication_structure.update_structure(
					structure_influence=structure_influence
				)
				break
		self.__client_authentication_structure_per_client_uuid_semphore.release()


class ClientAuthenticationManagerStructureFactory(StructureFactory):

	def __init__(self, *, openid_authentication_configuration: OpenidAuthenticationConfiguration):
		super().__init__()

		self.__openid_authentication_configuration = openid_authentication_configuration

	def get_structure(self) -> Structure:
		return ClientAuthenticationManagerStructure(
			openid_authentication_configuration=self.__openid_authentication_configuration
		)
