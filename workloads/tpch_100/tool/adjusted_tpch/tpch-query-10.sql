-- [origin]

select
	c_custkey,
	c_name,
	sum(l_extendedprice * (1 - l_discount)) as revenue,
	c_acctbal,
	n_name,
	c_address,
	c_phone,
	c_comment
from
	customer,
	orders,
	lineitem,
	nation
where
	c_custkey = o_custkey
	and l_orderkey = o_orderkey
	and cast(o_orderdate as Date) >= date '1994-04-01'
	and cast(o_orderdate as Date) < date '1994-04-01' + interval '3' month
	and l_returnflag = 'R'
	and c_nationkey = n_nationkey
group by
	c_custkey,
	c_name,
	c_acctbal,
	c_phone,
	n_name,
	c_address,
	c_comment
order by
	revenue desc 
limit 20 

-- [default] change join type

select
	c_custkey,
	c_name,
	sum(l_extendedprice * (1 - l_discount)) as revenue,
	c_acctbal,
	n_name,
	c_address,
	c_phone,
	c_comment
from
	lineitem
    left join orders on l_orderkey = o_orderkey
	left join customer on c_custkey = o_custkey
    left join nation on c_nationkey = n_nationkey
where


	cast(o_orderdate as Date) >= date '1994-04-01'
	and cast(o_orderdate as Date) < date '1994-04-01' + interval '3' month
	and l_returnflag = 'R'

group by
	c_custkey,
	c_name,
	c_acctbal,
	c_phone,
	n_name,
	c_address,
	c_comment
order by
	revenue desc 
limit 20 
