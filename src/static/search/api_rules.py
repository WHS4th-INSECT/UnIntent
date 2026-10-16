from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from src.static.search.dex_ir import (
    invocation_formals,
    invocation_receiver,
    parse_method_reference,
)
from src.static.model.values import InstructionIR

PENDING_INTENT = "Landroid/app/PendingIntent;"


@dataclass(frozen=True)
class FrameworkCallbackModel:
    framework: str
    registration_owner: str
    registration_name: str
    callback_owner: str
    callback_name: str
    parameter_fields: dict[tuple[str, int], str]


WEBVIEW_DOWNLOAD = FrameworkCallbackModel(
    framework="android.webkit.WebView",
    registration_owner="Landroid/webkit/WebView;",
    registration_name="setDownloadListener",
    callback_owner="Landroid/webkit/DownloadListener;",
    callback_name="onDownloadStart",
    parameter_fields={
        ("Ljava/lang/String;", 0): "download_url",
        ("Ljava/lang/String;", 1): "user_agent",
        ("Ljava/lang/String;", 2): "content_disposition",
        ("Ljava/lang/String;", 3): "mime_type",
        ("J", 4): "content_length",
    },
)

WEBVIEW_CLIENT = "Landroid/webkit/WebViewClient;"
WEBVIEW = "Landroid/webkit/WebView;"
WEB_NAVIGATION_CALLBACK_PARAMETERS = {
    ("shouldOverrideUrlLoading", "Ljava/lang/String;", 1),
    ("shouldOverrideUrlLoading", "Landroid/webkit/WebResourceRequest;", 1),
}

EXTERNAL_FIELD_APIS: dict[str, str] = {
    "getAction": "action",
    "getData": "data",
    "getDataString": "data",
    "getType": "type",
    "getFlags": "flags",
    "getExtras": "extras",
    "getClipData": "clip_data",
    "getSelector": "selector",
    "getCategories": "categories",
    "getStringExtra": "extra",
    "getCharSequenceExtra": "extra",
    "getBooleanExtra": "extra",
    "getByteExtra": "extra",
    "getShortExtra": "extra",
    "getIntExtra": "extra",
    "getLongExtra": "extra",
    "getFloatExtra": "extra",
    "getDoubleExtra": "extra",
    "getParcelableExtra": "extra",
    "getSerializableExtra": "extra",
    "getBundleExtra": "extra",
    "getStringArrayExtra": "extra",
    "getStringArrayListExtra": "extra",
    "getBooleanArrayExtra": "extra",
    "getByteArrayExtra": "extra",
    "getCharArrayExtra": "extra",
    "getShortArrayExtra": "extra",
    "getIntArrayExtra": "extra",
    "getLongArrayExtra": "extra",
    "getFloatArrayExtra": "extra",
    "getDoubleArrayExtra": "extra",
    "getCharSequenceArrayExtra": "extra",
    "getCharSequenceArrayListExtra": "extra",
    "getIntegerArrayListExtra": "extra",
    "getParcelableArrayExtra": "extra",
    "getParcelableArrayListExtra": "extra",
    "getQueryParameter": "query_parameter",
    "getQueryParameters": "query_parameter",
}

NESTED_INTENT_APIS = {
    "getParcelableExtra",
    "getSerializableExtra",
    "getParcelable",
}

COLLECTION_TYPES = {
    "Ljava/lang/Iterable;",
    "Ljava/util/Collection;",
    "Ljava/util/List;",
    "Ljava/util/Set;",
    "Ljava/util/Map;",
    "Ljava/util/Queue;",
    "Ljava/util/Deque;",
    "Ljava/util/Iterator;",
}

CONCRETE_COLLECTION_TYPES = {
    "Ljava/util/ArrayList;",
    "Ljava/util/LinkedList;",
    "Ljava/util/HashSet;",
    "Ljava/util/LinkedHashSet;",
    "Ljava/util/TreeSet;",
    "Ljava/util/HashMap;",
    "Ljava/util/LinkedHashMap;",
    "Ljava/util/TreeMap;",
    "Ljava/util/ArrayDeque;",
    "Ljava/util/concurrent/ConcurrentHashMap;",
    "Landroid/util/ArrayMap;",
    "Landroid/util/SparseArray;",
}

COLLECTION_WRITER_ARGUMENTS: dict[str, tuple[int, ...]] = {
    "add": (0,),
    "addFirst": (0,),
    "addLast": (0,),
    "offer": (0,),
    "offerFirst": (0,),
    "offerLast": (0,),
    "push": (0,),
    "set": (1,),
    "put": (1,),
    "replace": (1,),
}

COLLECTION_READERS = {
    "get",
    "first",
    "firstOrNull",
    "last",
    "lastOrNull",
    "elementAt",
    "elementAtOrNull",
    "next",
    "peek",
    "peekFirst",
    "peekLast",
    "poll",
    "pollFirst",
    "pollLast",
    "pop",
}


def external_field_api(name: str, owner: str | None = None) -> tuple[str, str] | None:
    """Return the canonical Intent getter name and field for direct/compat APIs.

    Kotlin extension and Java compatibility helpers commonly preserve the
    platform getter name and append ``Compat``. Treat only wrappers whose
    canonical getter is already in the source catalog as source APIs; this
    avoids guessing from arbitrary application method names.
    """

    canonical = name[:-6] if name.endswith("Compat") else name
    field = EXTERNAL_FIELD_APIS.get(canonical)
    if field is None:
        return None
    if owner is not None:
        if field == "query_parameter":
            if owner != "Landroid/net/Uri;":
                return None
        elif owner != "Landroid/content/Intent;" and "IntentCompat;" not in owner:
            return None
    return canonical, field


@dataclass(frozen=True)
class SinkRule:
    rule_id: str
    category: str
    owner_pattern: str
    method_names: tuple[str, ...]
    argument_indices: tuple[int, ...] = ()
    argument_types: tuple[str, ...] = ()
    argument_type_index: int | None = None
    include_receiver: bool = False
    # Retain effects with no value argument so existing CFG tracing can find their triggers.
    allow_control_only: bool = False

    def matches(self, instruction: InstructionIR, owner_lineage: tuple[str, ...] = ()) -> bool:
        parsed = parse_method_reference(instruction.reference)
        if parsed is None:
            return False
        owner, name, _descriptor = parsed
        owners = owner_lineage or (owner,)
        return name in self.method_names and any(
            re.fullmatch(self.owner_pattern, candidate) is not None for candidate in owners
        )

    def argument_registers(self, instruction: InstructionIR) -> tuple[int, ...]:
        registers: list[int] = []
        if self.include_receiver:
            receiver = invocation_receiver(instruction)
            if receiver is not None:
                registers.append(receiver)
        for formal_index, dex_type, register in invocation_formals(instruction):
            if (
                self.argument_indices
                and formal_index in self.argument_indices
                or self.argument_types
                and dex_type in self.argument_types
                and (self.argument_type_index is None or formal_index == self.argument_type_index)
            ):
                registers.append(register)
        return tuple(dict.fromkeys(registers))


ICC_METHODS = (
    "startActivity",
    "startActivityIfNeeded",
    "startActivityForResult",
    "startActivities",
    "startService",
    "startForegroundService",
    "stopService",
    "bindService",
    "sendBroadcast",
    "sendBroadcastAsUser",
    "sendOrderedBroadcast",
    "sendOrderedBroadcastAsUser",
    "sendStickyBroadcast",
    "sendStickyBroadcastAsUser",
    "sendStickyOrderedBroadcast",
    "sendStickyOrderedBroadcastAsUser",
)

DEFAULT_RULES: tuple[SinkRule, ...] = (
    # Component dispatch
    SinkRule(
        "ICC_DISPATCH",
        "icc",
        r"L.*;",
        ICC_METHODS,
        argument_types=("Landroid/content/Intent;", "[Landroid/content/Intent;"),
    ),

    # Web and externally handled resources
    SinkRule(
        "WEBVIEW_LOAD",
        "sensitive",
        r"Landroid/webkit/WebView;",
        ("loadUrl", "loadData", "loadDataWithBaseURL", "postUrl"),
        argument_indices=(0,),
    ),
    SinkRule(
        "WEBVIEW_SCRIPT",
        "sensitive",
        r"Landroid/webkit/WebView;",
        ("evaluateJavascript", "addJavascriptInterface"),
        argument_indices=(0, 1),
    ),
    SinkRule(
        "NOTIFICATION_DISPLAY",
        "sensitive",
        (
            r"Landroid/app/NotificationManager;|"
            r"Landroidx/core/app/NotificationManagerCompat;|"
            r"Landroid/support/v4/app/NotificationManagerCompat;"
        ),
        ("notify", "notifyAsPackage"),
        argument_types=("Landroid/app/Notification;",),
    ),
    SinkRule(
        "CUSTOM_TAB_LAUNCH",
        "sensitive",
        r"Landroidx/browser/customtabs/CustomTabsIntent;",
        ("launchUrl",),
        argument_types=("Landroid/net/Uri;",),
    ),
    SinkRule(
        "DOWNLOAD_MANAGER_ENQUEUE",
        "sensitive",
        r"Landroid/app/DownloadManager;",
        ("enqueue",),
        argument_types=("Landroid/app/DownloadManager$Request;",),
    ),

    # URI, file, and database access
    SinkRule(
        "CONTENT_RESOLVER_URI",
        "sensitive",
        r"Landroid/content/ContentResolver;",
        (
            "insert",
            "update",
            "delete",
            "openInputStream",
            "openOutputStream",
            "openFileDescriptor",
            "openAssetFileDescriptor",
            "openTypedAssetFileDescriptor",
            "bulkInsert",
            "applyBatch",
            "call",
        ),
        argument_indices=(0,),
    ),
    SinkRule(
        "URI_PERMISSION_GRANT",
        "sensitive",
        r"Landroid/content/Context.*;|Landroid/app/.*;",
        ("grantUriPermission", "revokeUriPermission"),
        argument_types=("Landroid/net/Uri;",),
    ),
    SinkRule(
        "FILE_STREAM_OPEN",
        "sensitive",
        r"Ljava/io/(FileInputStream|FileOutputStream|FileReader|FileWriter|PrintWriter);|Ljava/util/(zip/ZipFile|jar/JarFile);",
        ("<init>",),
        argument_types=("Ljava/lang/String;", "Ljava/io/File;"),
        argument_type_index=0,
    ),
    SinkRule(
        "RANDOM_ACCESS_FILE_OPEN",
        "sensitive",
        r"Ljava/io/RandomAccessFile;",
        ("<init>",),
        argument_indices=(0,),
    ),
    SinkRule(
        "FILE_MUTATION",
        "sensitive",
        r"Ljava/io/File;",
        (
            "createNewFile",
            "delete",
            "deleteOnExit",
            "mkdir",
            "mkdirs",
            "renameTo",
        ),
        argument_indices=(0,),
        include_receiver=True,
    ),
    SinkRule(
        "NIO_FILE_ACCESS",
        "sensitive",
        r"Ljava/nio/file/Files;",
        (
            "newInputStream",
            "newOutputStream",
            "readAllBytes",
            "readAllLines",
            "readString",
            "lines",
            "write",
            "writeString",
            "delete",
            "deleteIfExists",
            "createFile",
            "copy",
            "move",
        ),
        argument_types=("Ljava/nio/file/Path;",),
    ),
    SinkRule(
        "PARCEL_FILE_OPEN",
        "sensitive",
        r"Landroid/os/ParcelFileDescriptor;",
        ("open",),
        argument_types=("Ljava/io/File;",),
    ),
    SinkRule(
        "ANDROID_OS_FILE_OPEN",
        "sensitive",
        r"Landroid/system/Os;",
        ("open",),
        argument_indices=(0,),
    ),
    SinkRule(
        "CONTEXT_FILE_ACCESS",
        "sensitive",
        r"Landroid/content/Context.*;|Landroid/app/.*;",
        ("openFileInput", "openFileOutput", "deleteFile"),
        argument_indices=(0,),
    ),
    SinkRule(
        "SQL_EXECUTION",
        "sensitive",
        r"Landroid/database/sqlite/SQLiteDatabase;",
        ("rawQuery", "execSQL"),
        argument_indices=(0,),
    ),

    # Code and process execution
    SinkRule(
        "COMMAND_EXECUTION",
        "sensitive",
        r"Ljava/lang/Runtime;|Ljava/lang/ProcessBuilder;",
        ("exec", "<init>", "command"),
        argument_indices=(0,),
    ),
    SinkRule(
        "SHELL_COMMAND_SUBMISSION",
        "sensitive",
        r"Lcom/stericson/RootTools/execution/Shell;",
        ("add",),
        argument_types=("Lcom/stericson/RootTools/execution/Command;",),
        argument_type_index=0,
    ),
    SinkRule(
        "DYNAMIC_CODE_LOAD",
        "sensitive",
        r"Ldalvik/system/(BaseDexClassLoader|DexClassLoader|PathClassLoader|InMemoryDexClassLoader);",
        ("<init>",),
        argument_indices=(0,),
    ),
    SinkRule(
        "NATIVE_LIBRARY_LOAD",
        "sensitive",
        r"Ljava/lang/(System|Runtime);",
        ("load", "loadLibrary"),
        argument_indices=(0,),
    ),

    # Privileged device and application state changes
    SinkRule(
        "TELECOM_PLACE_CALL",
        "sensitive",
        r"Landroid/telecom/TelecomManager;",
        ("placeCall",),
        argument_indices=(0,),
    ),
    SinkRule(
        "TELECOM_CALL_CONTROL",
        "sensitive",
        r"Landroid/telecom/Call;|Landroid/telecom/TelecomManager;",
        ("answer", "reject", "disconnect", "acceptRingingCall", "endCall"),
        argument_indices=(0, 1),
        allow_control_only=True,
    ),
    SinkRule(
        "SETTINGS_WRITE",
        "sensitive",
        r"Landroid/provider/Settings\$(System|Secure|Global);",
        ("putInt", "putLong", "putFloat", "putString"),
        argument_indices=(1, 2),
    ),
    SinkRule(
        "PACKAGE_STATE_CHANGE",
        "sensitive",
        r"Landroid/content/pm/PackageManager;",
        ("setComponentEnabledSetting", "setApplicationEnabledSetting", "setPackagesSuspended"),
        argument_indices=(0, 1),
    ),
)

GUARD_KINDS = {
    "enforcePermission": "enforcing",
    "enforceCallingPermission": "enforcing",
    "enforceCallingOrSelfPermission": "enforcing",
    "enforceUriPermission": "enforcing",
    "enforceCallingUriPermission": "enforcing",
    "enforceCallingOrSelfUriPermission": "enforcing",
    "checkPermission": "check",
    "checkCallingPermission": "check",
    "checkCallingOrSelfPermission": "check",
    "checkUriPermission": "check",
    "checkCallingUriPermission": "check",
    "checkCallingOrSelfUriPermission": "check",
    "checkComponentPermission": "check",
    "checkSignatures": "check",
    "checkUidSignatures": "check",
    "getCallingUid": "identity",
    "getCallingPid": "identity",
    "getCallingPackage": "identity",
    "getCallingActivity": "identity",
}

GUARD_DESCRIPTIONS = {
    "enforcing": "caller permission enforcement",
    "check": "caller authorization check",
    "identity": "caller identity inspection",
}


def load_rules(path: Path | None = None) -> tuple[SinkRule, ...]:
    if path is None:
        return DEFAULT_RULES
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise TypeError("sink config must contain a JSON array")
    custom = tuple(
        SinkRule(
            rule_id=str(item["rule_id"]),
            category=str(item.get("category", "sensitive")),
            owner_pattern=str(item["owner_pattern"]),
            method_names=tuple(str(value) for value in item["method_names"]),
            argument_indices=tuple(int(value) for value in item.get("argument_indices", [])),
            argument_types=tuple(str(value) for value in item.get("argument_types", [])),
            argument_type_index=(
                int(item["argument_type_index"])
                if item.get("argument_type_index") is not None else None
            ),
            include_receiver=bool(item.get("include_receiver", False)),
            allow_control_only=bool(item.get("allow_control_only", False)),
        )
        for item in payload
    )
    return (*DEFAULT_RULES, *custom)
