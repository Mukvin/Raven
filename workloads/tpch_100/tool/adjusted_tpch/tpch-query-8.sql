-- [origin]

select
	o_year,
	sum(case
		when nation = 'INDIA' then volume
		else 0
	end) / sum(volume) as mkt_share
from
	(
		select
			extract(year from cast(o_orderdate as Date)) as o_year,
			l_extendedprice * (1 - l_discount) as volume,
			n2.n_name as nation
		from
			part,
			supplier,
			lineitem,
			orders,
			customer,
			nation n1,
			nation n2,
			region
		where
			p_partkey = l_partkey
			and s_suppkey = l_suppkey
			and l_orderkey = o_orderkey
			and o_custkey = c_custkey
			and c_nationkey = n1.n_nationkey
			and n1.n_regionkey = r_regionkey
			and r_name = 'ASIA'
			and s_nationkey = n2.n_nationkey
			and cast(o_orderdate as Date) between date '1995-01-01' and date '1996-12-31'
			and p_type = 'MEDIUM POLISHED TIN'
	) as all_nations
group by
	o_year
order by
	o_year 
  
-- [default] change join type

select
	o_year,
	sum(case
		when nation = 'INDIA' then volume
		else 0
	end) / sum(volume) as mkt_share
from
	(
		select
			extract(year from cast(o_orderdate as Date)) as o_year,
			l_extendedprice * (1 - l_discount) as volume,
			n2.n_name as nation
		from
			lineitem
		    left join part on l_partkey = p_partkey
		    left join supplier on l_suppkey = s_suppkey
			left join orders on l_orderkey = o_orderkey
			left join customer on o_custkey = c_custkey
		    left join nation n1 on c_nationkey = n1.n_nationkey
		    left join nation n2 on s_nationkey = n2.n_nationkey
		    left join region on n1.n_regionkey = r_regionkey
		where
			r_name = 'ASIA'
			and cast(o_orderdate as Date) between date '1995-01-01' and date '1996-12-31'
			and p_type = 'MEDIUM POLISHED TIN'
	) as all_nations
group by
	o_year
order by
	o_year 