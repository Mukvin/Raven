from enum import Enum


class InstanceTag(Enum):
    QUERY_MASTER = "#querymaster#alluxiomaster#"
    BUILD_MASTER = "#buildmaster#alluxiomaster#"
    QUERY_WORKER = "#queryworker#alluxioworker#"
    BUILD_WORKER = "#buildworker#"
    EDGE = "#ke#sparkclient#"
    KC = "#kc#zookeeper#influxdb#"
    KI = "#ki#mdx#"
    MDX = "#ki#mdx#"
    ZK = "#zookeeper#"
    ALLUXIO = "#alluxiomaster#"

# EDGE == KE NODE
class InstanceTypeAttr(Enum):
    QUERY = "Query", 0, "workNodeCount", ""
    BUILD = "Build", 1, "workNodeCount", ""
    EDGE = "Edge", 0, "edgeNodeCount", ""
    KI = "KI", 0, "kiNodeCount", "installKI"
    MDX = "MDX", 0, "kiNodeCount", "installMDX"

