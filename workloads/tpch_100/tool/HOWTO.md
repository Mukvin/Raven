This document is for those who want to re-generate TPCH-100 query workload.

Most common users don't need to read this article.



## How are the queries generated?

For TPCH query generation we use https://github.com/gregrahn/tpch-kit/ , follow its instructions to learn how to use it. 

We can further use the following code snippet to generate thousands of TPCH queries: 

```bash
for ((i=1;i<=1000;i++)); do
        for ((j=1;j<=22;j++)); do
                ./qgen -v -c -s 100 ${j} > scale100_queries_sample/tpch-query-${j}-${i}.sql
                sleep 1 # otherwise consecutive queries will be identical
        done
done
```

This code snippet may take a few hours to finish.

What the above code does is to  generate random queries from 22 TPCH query templates for 1000 times. Now we get 1000*22 = 22000 distinct (almost) queries, use following command to check how many queries are duplicated: 

```
find . -type f -exec sed -i  ".bak"  '/^--/d' {} \; # delete comment lines start with "--"

# find . -type f -name "*.sql" |  xargs md5 -q | sort | uniq | wc -l
# on my MAC this command return 7377, which means (22000 - 7377) queries are duplicate

for ((j=1;j<=22;j++)); do
	print "count dedup queries (from 1000 queries) for query template ${j}:"
    find . -type f -name "tpch-query-${j}-*.sql" |  xargs md5 -q | sort | uniq | wc -l
done
```



> count dedup queries for query template 1
>       61
> count dedup queries for query template 2
>      590
> count dedup queries for query template 3
>      153
> count dedup queries for query template 4
>       58
> count dedup queries for query template 5
>       25
> count dedup queries for query template 6
>       80
> count dedup queries for query template 7
>      465
> count dedup queries for query template 8
>      824
> count dedup queries for query template 9
>       89
> count dedup queries for query template 10
>       24
> count dedup queries for query template 11
>       25
> count dedup queries for query template 12
>      210
> count dedup queries for query template 13
>       16
> count dedup queries for query template 14
>       60
> count dedup queries for query template 15
>       58
> count dedup queries for query template 16
>     1000
> count dedup queries for query template 17
>      647
> count dedup queries for query template 18
>        4
> count dedup queries for query template 19
>     1000
> count dedup queries for query template 20
>      963
> count dedup queries for query template 21
>       25
> count dedup queries for query template 22
>     1000



after 22000 queries ready, we can use the script in `workloads/tpch_100/tool/generate_tpch_100_query_script.py`  to generate the `query script`for our workload.