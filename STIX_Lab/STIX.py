from stix2.v21 import *
import uuid

attack_pattern = AttackPattern(
    type="attack-pattern",
    spec_version="2.1",
    id=str("attack-pattern--" + str(uuid.uuid4())),
    created="2021-10-20T15:50:10.983Z",
    modified="2021-10-21T21:15:04.127Z",
    name="Failed autentication sourced: external network"
)

indicator = Indicator(
    id=str("indicator--" + str(uuid.uuid4())),
    created="2021-10-20T13:49:37.079Z",
    modified="2021-10-21T13:49:37.079Z",
    name="SSHD log alerting",
    description="SSHD flagged failed connection attemps though SSH from an external network.",
    indicator_types=["malicious-activity"],
    pattern=["ipv4-addr:value = '175.45.177-179.*'"],
    pattern_type="SSH",
    valid_from="2021-10-20T13:49:37.079000Z"
)

intrusion_set = IntrusionSet(
    type="intrusion-set",
    spec_version="2.1",
    id=str("intrusion-set--" + str(uuid.uuid4())),
    created="2021-10-20T15:50:10.983Z",
    modified="2021-10-21T15:50:10.983Z",
    name="Hatfield?",
    description="Some dirty boys with too much free time on their hands",
    first_seen="2021-10-21T12:50:40.123Z",
    resource_level="open source/ custom",
    primary_motivation="revenge",
    goals=["Persistence in various blue team systems to provide learning capabilities"],
    secondary_motivations=["development of personal TTPs"],
    aliases=["No sleep gang"]
)

observed_data = ObservedData(
    id=str("observed-data--" + str(uuid.uuid4())),
    created="2021-10-20T19:37:11.213Z",
    modified="2021-10-21T19:37:11.213Z",
    first_observed="2021-10-21T21:37:11.213Z",
    last_observed="2021-10-30T21:37:11.213Z",
    number_observed=1,
    spec_version="2.1",
    type="observed-data",
    object_refs=[str("file--" + str(uuid.uuid4()))]
)

vulnerability = Vulnerability(
    id=str("vulnerability--" + str(uuid.uuid4())),
    created="2021-10-20T19:37:11.213Z",
    modified="2021-10-21T19:37:11.213Z",
    name="N/A currently",
    description="Basic SSH access attempt, proper configuration is key"
)

identity = Identity(
    id=str("identity--" + str(uuid.uuid4())),
    created="2021-10-20T15:50:10.564Z",
    modified="2021-10-21T15:50:10.564Z",
    name="APT 420 - Dirty Boys",
    identity_class="organization",
    contact_information="info@DB.org",
    roles=["Cyber Security"],
    sectors=["technology"],
    type="identity"
)


course_of_action = CourseOfAction(
    id=str("course-of-action--" + str(uuid.uuid4())),
    created="2021-10-20T19:37:11.213Z",
    modified="2021-10-21T19:37:11.213Z",
    name="",
    description=""
)

malware = Malware(
    id=str("malware--" + str(uuid.uuid4())),
    created="2021-10-20T09:15:17.182Z",
    modified="2021-10-21T09:15:17.182Z",
    name="Potential injection",
    malware_types=["backdoor", "remote-access-trojan"],
    description="Poor SSH configuration poses opportunity for malware injection",
    is_family=False
)

malware_analysis = MalwareAnalysis(
    id=str("malware-analysis--" + str(uuid.uuid4())),
    created="2021-10-20T09:15:17.182Z",
    modified="2021-10-21T09:15:17.182Z",
    product="Canonical",
    result="malicious"
)

bundle = Bundle(objects=[attack_pattern, indicator, intrusion_set, observed_data, vulnerability, identity, course_of_action, malware, malware_analysis])
print(bundle.serialize(pretty=True))
