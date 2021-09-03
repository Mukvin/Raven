-- [origin]

select
	n_name,
	sum(l_extendedprice * (1 - l_discount)) as revenue
from
	customer,
	orders,
	lineitem,
	supplier,
	nation,
	region
where
	c_custkey = o_custkey
	and l_orderkey = o_orderkey
	and l_suppkey = s_suppkey
	and c_nationkey = s_nationkey
	and s_nationkey = n_nationkey
	and n_regionkey = r_regionkey
	and r_name = 'EUROPE'
	and cast(o_orderdate as Date) >= date '1993-01-01'
	and cast(o_orderdate as Date) < date '1993-01-01' + interval '1' year
group by
	n_name
order by
	revenue desc 


-- [default] change join type

select
	sn.n_name,
	sum(l_extendedprice * (1 - l_discount)) as revenue
from
	lineitem
    left join orders on l_orderkey = o_orderkey
    left join customer on o_custkey = c_custkey
    left join nation cn on c_nationkey = cn.n_nationkey
    left join supplier on l_suppkey = s_suppkey
    left join nation sn on s_nationkey = sn.n_nationkey
    left join region on sn.n_regionkey = r_regionkey
where
	cn.n_name = sn.n_name
	and r_name = 'EUROPE'
	and cast(o_orderdate as Date) >= date '1993-01-01'
	and cast(o_orderdate as Date) < date '1993-01-01' + interval '1' year
group by
	sn.n_name
order by
	revenue desc 


  
