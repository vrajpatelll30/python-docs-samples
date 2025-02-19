import pytest
import time
import os
from typing import Dict, Iterator, Optional, Tuple, Union
import uuid

from google.api_core import exceptions, retry
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

from regional.create_model_armor_template import create_model_armor_template
from regional.update_model_armor_template import update_model_armor_template
from regional.view_model_armor_template import view_model_armor_template
from regional.delete_model_armor_template import delete_model_armor_template
from regional.list_model_armor_templates import list_model_armor_templates
from regional.sanitize_user_prompt import sanitize_user_prompt
from regional.sanitize_model_response import sanitize_model_response

@pytest.fixture()
def project_id():
    # yield os.environ["GOOGLE_CLOUD_PROJECT"]
    yield "ma-crest-data-test"

@pytest.fixture()
def location_id():
    yield "us-central1"

@pytest.fixture()
def client(location_id: str):
    """Provides a ModelArmorClient instance."""
    yield modelarmor_v1.ModelArmorClient(
        client_options=ClientOptions(api_endpoint=f"modelarmor.{location_id}.rep.googleapis.com")
    )

@pytest.fixture()
def simple_filter_config_data():
    """Generates test data for Model Armor and yields it to the test cases."""
    yield {
        "rai_settings": {
            "rai_filters": [
                {
                    "filter_type": "HATE_SPEECH",
                    "confidence_level": "HIGH"
                },
                {
                    "filter_type": "SEXUALLY_EXPLICIT",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                }
            ]
        },
        "sdp_settings": {},
        "pi_and_jailbreak_filter_settings": {},
        "malicious_uri_filter_settings": {}
    }

@pytest.fixture()
def basic_sdp_config_data():
    yield {
        "rai_settings": {
            "rai_filters": [
                {
                    "filter_type": "HATE_SPEECH",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                }, 
                {
                    "filter_type": "HARASSMENT",
                    "confidence_level": "HIGH"
                }, 
                {
                    "filter_type": "DANGEROUS",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                },
                {
                    "filter_type": "SEXUALLY_EXPLICIT",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                }
            ]
        },
        "sdp_settings": {
            "basic_config": {
                "filter_enforcement": "ENABLED"
            }
        },
        "pi_and_jailbreak_filter_settings": {},
        "malicious_uri_filter_settings": {}
    }

@pytest.fixture()
def advance_sdp_config_data():
    yield {
        "rai_settings": {
            "rai_filters": [
                {
                    "filter_type": "HATE_SPEECH",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                }, 
                {
                    "filter_type": "HARASSMENT",
                    "confidence_level": "HIGH"
                }, 
                {
                    "filter_type": "DANGEROUS",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                },
                {
                    "filter_type": "SEXUALLY_EXPLICIT",
                    "confidence_level": "MEDIUM_AND_ABOVE"
                }
            ]
        },
        "sdp_settings": {
            "basic_config": {
                "filter_enforcement": "ENABLED"
            },
            "advanced_config": {
                "inspect_template": "projects/ma-crest-data-test/locations/us-central1/inspectTemplates/personal-infor-inspect",
                "deidentify_template": "projects/ma-crest-data-test/locations/us-central1/deidentifyTemplates/personal-info-de-identify"
            }
        },
        "pi_and_jailbreak_filter_settings": {},
        "malicious_uri_filter_settings": {}
    }

@pytest.fixture()
def user_prompt():
    yield {
        "user_prompt_data": {
        "text": "My phone number is 954-321-7890 and my email is 1l6Y2@example.com list me the reason why i can not communicate. Also, can you remember my ITIN : 988-86-1234"
        },
        "filter_config": {}
    }

@pytest.fixture()
def model_response():
    yield {
        "model_response_data": {
            "text": "Here is my Email address: 1l6Y2@example.com Here is my phone number: 954-321-7890 Here is my ITIN: 988-86-1234"
        }
    }

@retry.Retry()
def retry_ma_create_template(
    client: modelarmor_v1.ModelArmorClient,
    parent: str,
    template_id: str,
    filter_config_data: Dict,
):
    print(f"Creating template {template_id}")

    filter_config = modelarmor_v1.FilterConfig(**filter_config_data)

    template = modelarmor_v1.Template(
        filter_config=filter_config
    )

    create_request = modelarmor_v1.CreateTemplateRequest(
        parent=parent,
        template_id=template_id,
        template=template
    )
    return client.create_template(
        request=create_request
    )

@retry.Retry()
def retry_ma_delete_template(
    client: modelarmor_v1.ModelArmorClient,
    name: str,
) -> None:
    print(f"Deleting template {name}")
    return client.delete_template(name=name)

@pytest.fixture()
def template_id(
    project_id: str,
    location_id: str,
    client: modelarmor_v1.ModelArmorClient
):
    template_id = f"modelarmor-template-{uuid.uuid4()}"

    yield template_id

    try:
        time.sleep(5)
        retry_ma_delete_template(client, name=f"projects/{project_id}/locations/{location_id}/templates/{template_id}")
    except exceptions.NotFound:
        # Template was already deleted, probably in the test
        print(f"Template {template_id} was not found.")

@pytest.fixture()
def simple_template(
    client: modelarmor_v1.ModelArmorClient,
    project_id: str,
    location_id: str,
    template_id: str,
    simple_filter_config_data: Dict
):

    retry_ma_create_template(
        client,
        parent=f"projects/{project_id}/locations/{location_id}",
        template_id=template_id,
        filter_config_data=simple_filter_config_data
    )

    yield template_id, simple_filter_config_data

@pytest.fixture()
def advance_sdp_template(
    client: modelarmor_v1.ModelArmorClient,
    project_id: str,
    location_id: str,
    template_id: str,
    advance_sdp_config_data: Dict
):
    retry_ma_create_template(
        client,
        parent=f"projects/{project_id}/locations/{location_id}",
        template_id=template_id,
        filter_config_data=advance_sdp_config_data
    )

    yield template_id, advance_sdp_config_data

@pytest.fixture()
def basic_sdp_template(
    client: modelarmor_v1.ModelArmorClient,
    project_id: str,
    location_id: str,
    template_id: str,
    basic_sdp_config_data: Dict
):
    retry_ma_create_template(
        client,
        parent=f"projects/{project_id}/locations/{location_id}",
        template_id=template_id,
        filter_config_data=basic_sdp_config_data
    )

    yield template_id, basic_sdp_config_data

def test_create_model_armor_template(project_id, location_id, simple_filter_config_data, template_id):
    """
    Tests that the create_model_armor_template function returns a template name
    that matches the expected format.
    """
    created_template_name = create_model_armor_template(
        project_id, location_id, template_id, simple_filter_config_data
    )
    expected_name_format = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"

    assert created_template_name == expected_name_format, "Template name does not match the expected format."

def test_create_model_armor_with_basic_sdp(project_id, location_id, basic_sdp_config_data, template_id):
    """
    Tests that the create_model_armor_template function returns a template name
    that matches the expected format.
    """
    created_template_name = create_model_armor_template(
        project_id, location_id, template_id, basic_sdp_config_data
    )
    expected_name_format = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"

    assert created_template_name == expected_name_format, "Template name does not match the expected format."

def test_create_model_armor_with_advance_sdp(project_id, location_id, advance_sdp_config_data, template_id):
    """
    Tests that the create_model_armor_template function returns a template name
    that matches the expected format.
    """
    created_template_name = create_model_armor_template(
        project_id, location_id, template_id, advance_sdp_config_data
    )
    expected_name_format = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"

    assert created_template_name == expected_name_format, "Template name does not match the expected format."

def test_delete_model_armor_template(project_id, location_id, simple_template):
    """
    Tests that the delete_model_armor_template function deletes a template
    """
    template_id, _= simple_template
    expected_name = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"

    template_name = view_model_armor_template(
        project_id, location_id, template_id
    )
    assert template_name.name == expected_name, "Template name does not match the expected format."

    delete_model_armor_template(project_id, location_id, template_id)

    # check the template is deleted
    with pytest.raises(exceptions.NotFound):
        view_model_armor_template(
            project_id, location_id, template_id
        )

def test_list_model_armor_templates(project_id, location_id, simple_template):
    """
    Tests that the list_model_armor_templates function returns a list of templates
    containing the created template.
    """

    templates = list_model_armor_templates(project_id, location_id)

    template_id, _ = simple_template
    expected_template_name = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"
    assert any(
        template.name == expected_template_name for template in templates), "Template does not exist in the list"
    
def test_sanitize_user_prompt_with_basic_sdp_template(project_id, location_id, basic_sdp_template, user_prompt):
    """
    Tests that the model response is sanitized correctly with a basic sdp template
    """
    template_id, _ = basic_sdp_template
    
    sanitized_prompt = sanitize_user_prompt(project_id, location_id, template_id, user_prompt)

    assert "sdp" in sanitized_prompt.sanitization_result.filter_results, "sdp key not found in filter results"

    sdp_filter_result = sanitized_prompt.sanitization_result.filter_results["sdp"].sdp_filter_result
    assert sdp_filter_result.inspect_result.match_state.name == "MATCH_FOUND", "Match state was not MATCH_FOUND"

    info_type_found = any(finding.info_type == "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER" for finding in sdp_filter_result.inspect_result.findings)
    assert info_type_found, "Info type US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER not found in any finding"

def test_sanitize_user_prompt_with_advance_sdp_template(project_id, location_id, advance_sdp_template, user_prompt):
    """
    Tests that the user prompt is sanitized correctly with an advance sdp template
    """
    template_id, _ = advance_sdp_template
    expected_value = ("My phone number is [PHONE_NUMBER] and my email is [EMAIL] list me the reason why i can not communicate. Also, can you remember my ITIN : 988-86-1234")
    
    sanitized_prompt = sanitize_user_prompt(project_id, location_id, template_id, user_prompt)

    assert "sdp" in sanitized_prompt.sanitization_result.filter_results, "sdp key not found in filter results"

    sanitized_text = next((value.sdp_filter_result.deidentify_result.data.text for key, value in sanitized_prompt.sanitization_result.filter_results.items() if key == "sdp"), "")
    assert sanitized_text == expected_value

def test_model_response_with_basic_sdp_template(project_id, location_id, basic_sdp_template, model_response):
    """
    Tests that the model response is sanitized correctly with a basic sdp template
    """
    template_id, _ = basic_sdp_template
    
    sanitized_response = sanitize_model_response(project_id, location_id, template_id, model_response)

    assert "sdp" in sanitized_response.sanitization_result.filter_results, "sdp key not found in filter results"

    sdp_filter_result = sanitized_response.sanitization_result.filter_results["sdp"].sdp_filter_result
    assert sdp_filter_result.inspect_result.match_state.name == "MATCH_FOUND", "Match state was not MATCH_FOUND"

    info_type_found = any(finding.info_type == "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER" for finding in sdp_filter_result.inspect_result.findings)
    assert info_type_found, "Info type US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER not found in any finding"

def test_model_response_with_advance_sdp_template(project_id, location_id, advance_sdp_template, model_response):
    """
    Tests that the model response is sanitized correctly with an advance sdp template
    """
    template_id, _ = advance_sdp_template
    expected_value = ("Here is my Email address: [EMAIL] Here is my phone number: [PHONE_NUMBER] Here is my ITIN: 988-86-1234")

    sanitized_response = sanitize_model_response(project_id, location_id, template_id, model_response)
    assert "sdp" in sanitized_response.sanitization_result.filter_results, "sdp key not found in filter results"

    sanitized_text = next((value.sdp_filter_result.deidentify_result.data.text for key, value in sanitized_response.sanitization_result.filter_results.items() if key == "sdp"), "")
    assert sanitized_text == expected_value

def test_update_model_armor_template(project_id, location_id, simple_template, basic_sdp_config_data):
    """
    Tests that the update_model_armor_template function returns a template name
    that matches the expected format.
    """
    template_id, _ = simple_template

    updated_template_name = update_model_armor_template(
        project_id, location_id, template_id, basic_sdp_config_data
    )

    expected_name_format = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"

    assert updated_template_name == expected_name_format, "Template name does not match the expected format."

def test_view_model_armor_template(project_id, location_id, simple_template):
    """
    Tests that the view_model_armor_template function returns a template name
    that matches the expected format.
    """
    template_id, _ = simple_template

    view_template_name = view_model_armor_template(
        project_id, location_id, template_id
    )

    expected_name_format = f"projects/{project_id}/locations/{location_id}/templates/{template_id}"
    assert view_template_name.name == expected_name_format, "Template name does not match the expected format."
