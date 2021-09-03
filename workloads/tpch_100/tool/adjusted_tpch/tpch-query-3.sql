-- [origin]

select
	l_orderkey,
	sum(l_extendedprice * (1 - l_discount)) as revenue,
	o_orderdate,
	o_shippriority
from
	customer,
	orders,
	lineitem
where
	c_mktsegment = 'HOUSEHOLD'
	and c_custkey = o_custkey
	and l_orderkey = o_orderkey
	and cast(o_orderdate as Date) < date '1995-03-28'
	and cast(l_shipdate as Date) > date '1995-03-28'
group by
	l_orderkey,
	o_orderdate,
	o_shippriority
order by
	revenue desc,
	o_orderdate 
limit 10 

-- [default] change join type


select
	l_orderkey,
	sum(l_extendedprice * (1 - l_discount)) as revenue,
	o_orderdate,
	o_shippriority
from
	lineitem
    left join orders on l_orderkey = o_orderkey
    left join customer on c_custkey = o_custkey
where
	c_mktsegment = 'HOUSEHOLD'
	and cast(o_orderdate as Date) < date '1995-03-28'
	and cast(l_shipdate as Date) > date '1995-03-28'
group by
	l_orderkey,
	o_orderdate,
	o_shippriority
order by
	revenue desc,
	o_orderdate 
limit 10 