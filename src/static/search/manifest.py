from __future__ import annotations

from typing import Any

from src.static.model.values import Component, EntryPoint, IntentFilter

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def android_attr(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def qualify(package_name: str, class_name: str) -> str:
    if class_name.startswith("."):
        return package_name + class_name
    if "." not in class_name:
        return f"{package_name}.{class_name}"
    return class_name


def descriptor(class_name: str) -> str:
    return "L" + class_name.replace(".", "/") + ";"


def _values(element: Any, child_tag: str, attribute: str = "name") -> tuple[str, ...]:
    return tuple(
        value
        for child in element.findall(child_tag)
        if (value := child.get(android_attr(attribute)))
    )


def _filter(element: Any) -> IntentFilter:
    data = element.findall("data")
    return IntentFilter(
        actions=_values(element, "action"),
        categories=_values(element, "category"),
        schemes=tuple(value for child in data if (value := child.get(android_attr("scheme")))),
        hosts=tuple(value for child in data if (value := child.get(android_attr("host")))),
        paths=tuple(
            value
            for child in data
            for attribute in ("path", "pathPrefix", "pathPattern")
            if (value := child.get(android_attr(attribute)))
        ),
        mime_types=tuple(value for child in data if (value := child.get(android_attr("mimeType")))),
    )


def parse_components(apk: Any) -> tuple[list[Component], dict[str, Any]]:
    manifest = apk.get_android_manifest_xml()
    package_name = str(apk.get_package())
    application = manifest.find("application")
    if application is None:
        return [], {"package": package_name}

    permission_levels: dict[str, str] = {}
    try:
        from androguard.core.api_specific_resources import load_permissions

        api_level = int(apk.get_target_sdk_version() or 1)
        permission_levels.update(
            {
                name: str(details.get("protectionLevel", "normal"))
                for name, details in load_permissions(api_level).items()
            }
        )
    except (ImportError, OSError, TypeError, ValueError):
        pass
    for permission in manifest.findall("permission"):
        name = permission.get(android_attr("name"))
        level = permission.get(android_attr("protectionLevel"))
        if name:
            permission_levels[name] = level or "normal"

    application_permission = application.get(android_attr("permission"))
    application_enabled = application.get(android_attr("enabled"), "true").lower() != "false"
    components: list[Component] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for element in application.findall(tag):
            raw_name = element.get(android_attr("name"))
            if not raw_name:
                continue
            enabled = application_enabled and (
                element.get(android_attr("enabled"), "true").lower() != "false"
            )
            filters = tuple(_filter(item) for item in element.findall("intent-filter"))
            exported_value = element.get(android_attr("exported"))
            if exported_value is not None:
                exported = exported_value.lower() == "true"
            elif tag == "provider":
                try:
                    exported = int(apk.get_target_sdk_version() or 0) <= 16
                except (TypeError, ValueError):
                    exported = False
            else:
                exported = bool(filters)

            public_name = qualify(package_name, raw_name)
            if tag == "activity-alias":
                target = element.get(android_attr("targetActivity")) or raw_name
                code_class = qualify(package_name, target)
                component_type = "activity"
            else:
                code_class = public_name
                component_type = tag
            permission = element.get(android_attr("permission")) or application_permission
            components.append(
                Component(
                    name=public_name,
                    code_class=code_class,
                    descriptor=descriptor(code_class),
                    component_type=component_type,
                    exported=exported,
                    enabled=enabled,
                    permission=permission,
                    permission_protection_level=(
                        permission_levels.get(permission) if permission else None
                    ),
                    filters=filters,
                )
            )
    return components, {
        "package": package_name,
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
    }


def entry_points(components: list[Component]) -> list[EntryPoint]:
    return [
        EntryPoint(
            component=component.name,
            component_type=component.component_type,
            permission=component.permission,
            filters=component.filters,
            provenance=component.entry_provenance or "manifest_enabled",
            runtime_activation_evidence=component.runtime_activation_evidence,
            runtime_receiver_evidence=component.runtime_receiver_evidence,
        )
        for component in components
        if component.is_entry_point
    ]


def strong_permission(component: Component) -> bool:
    if component.permission is None:
        return False
    level = (component.permission_protection_level or "").lower().strip()
    if "signature" in level:
        return True
    try:
        numeric = int(level, 0)
    except ValueError:
        try:
            numeric = int(level, 10)
        except ValueError:
            return False
    return (numeric & 0xF) in {2, 3}


def generic_attacker_can_invoke(component: Component) -> bool:
    """Whether an ordinary third-party app can invoke this exported Entry."""

    if not component.is_entry_point:
        return False
    if component.permission is None:
        return True
    level = (component.permission_protection_level or "").lower().strip()
    if not level:
        # An unresolved permission declaration is not evidence of a generic
        # attacker surface.
        return False
    if "signature" in level:
        return False
    try:
        numeric = int(level, 0)
    except ValueError:
        try:
            numeric = int(level, 10)
        except ValueError:
            words = {
                item.strip()
                for item in level.replace("|", " ").split()
                if item.strip()
            }
            return bool(words.intersection({"normal", "dangerous"}))
    return (numeric & 0xF) in {0, 1}
