-- [origin]

select
	nation,
	o_year,
	sum(amount) as sum_profit
from
	(
		select
			n_name as nation,
			extract(year from cast(o_orderdate as Date)) as o_year,
			l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity as amount
		from
			part,
			supplier,
			lineitem,
			partsupp,
			orders,
			nation
		where
			s_suppkey = l_suppkey
			and ps_suppkey = l_suppkey
			and ps_partkey = l_partkey
			and p_partkey = l_partkey
			and o_orderkey = l_orderkey
			and s_nationkey = n_nationkey
			and p_name like '%grey%'
	) as profit
group by
	nation,
	o_year
order by
	nation,
	o_year desc 
  

-- [default] change join type

select
	nation,
	o_year,
	sum(amount) as sum_profit
from
	(
		select
			n_name as nation,
			extract(year from cast(o_orderdate as Date)) as o_year,
			l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity as amount
		from
			lineitem
			left join part on l_partkey = p_partkey
			left join supplier on l_suppkey = s_suppkey
			left join partsupp on l_suppkey = ps_suppkey and l_partkey = ps_partkey
			left join orders on l_orderkey = o_orderkey
			left join nation on s_nationkey = n_nationkey
		where
			
			p_name like '%grey%'
	) as profit
group by
	nation,
	o_year
order by
	nation,
	o_year desc 
  