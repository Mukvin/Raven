-- [origin]

select
	c_name,
	c_custkey,
	o_orderkey,
	o_orderdate,
	o_totalprice,
	sum(l_quantity)
from
	customer,
	orders,
	lineitem
where
	o_orderkey in (
		select
			l_orderkey
		from
			lineitem
		group by
			l_orderkey having
				sum(l_quantity) > 313
	)
	and c_custkey = o_custkey
	and o_orderkey = l_orderkey
group by
	c_name,
	c_custkey,
	o_orderkey,
	o_orderdate,
	o_totalprice
order by
	o_totalprice desc,
	o_orderdate 
limit 100 

-- [default] change join type + simply

select
    c_name,
    c_custkey,
    o_orderkey,
    o_orderdate,
    o_totalprice,
    sum(l_quantity)
from
    lineitem
    left join orders on l_orderkey = o_orderkey
    left join customer on o_custkey = c_custkey
where
    o_orderkey is not null
group by
    c_name,
    c_custkey,
    o_orderkey,
    o_orderdate,
    o_totalprice
having
    sum(l_quantity) > 313
order by
    o_totalprice desc,
    o_orderdate 
limit 100
