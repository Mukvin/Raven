This is a default benchmark workload based on TPCH.

If you want to replace this workload with your own, you can reuse this file structure


## About query_script

### Why query_script_am and query_script_am?
For:

 1. some workloads designer may put many queries containing filters with regard to latest loaded data's timestamp
 e.g. select count(*) from fact where dt = '<DAY_1>' before incr data,
 and select count(*) from fact where dt = '<DAY_2>' after incr data.
 2. some workload designer may what different query frequency

 In these cases they may want separate queries for AM and PM.
 However, IN MOST CASES JUST DUPLICATE ONE QUERY_SCRIPT TO ANOTHER QUERY_SCRIPT.

### What is at_second?
It specifies how many seconds after ON_AM_QUERY_START(or ON_PM_QUERY_START) this query will be summited to the
query execution pool, whose max worker size is denoted by max_worker_num
According to our design, ON_AM_QUERY_FINISH - ON_AM_QUERY_START = 5h, so at_second should NOT exceed 3600 * 5
