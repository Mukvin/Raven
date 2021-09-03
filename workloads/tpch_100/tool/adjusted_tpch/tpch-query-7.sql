-- [origin]

select
	supp_nation,
	cust_nation,
	l_year,
	sum(volume) as revenue
from
	(
		select
			n1.n_name as supp_nation,
			n2.n_name as cust_nation,
			extract(year from cast(l_shipdate as Date)) as l_year,
			l_extendedprice * (1 - l_discount) as volume
		from
			supplier,
			lineitem,
			orders,
			customer,
			nation n1,
			nation n2
		where
			s_suppkey = l_suppkey
			and o_orderkey = l_orderkey
			and c_custkey = o_custkey
			and s_nationkey = n1.n_nationkey
			and c_nationkey = n2.n_nationkey
			and (
				(n1.n_name = 'INDIA' and n2.n_name = 'MOZAMBIQUE')
				or (n1.n_name = 'MOZAMBIQUE' and n2.n_name = 'INDIA')
			)
			and cast(l_shipdate as Date) between date '1995-01-01' and date '1996-12-31'
	) as shipping
group by
	supp_nation,
	cust_nation,
	l_year
order by
	supp_nation,
	cust_nation,
	l_year 
 

-- [default] change join type

select
	supp_nation,
	cust_nation,
	l_year,
	sum(volume) as revenue
from
	(
		select
			n1.n_name as supp_nation,
			n2.n_name as cust_nation,
			extract(year from cast(l_shipdate as Date)) as l_year,
			l_extendedprice * (1 - l_discount) as volume
		from
			lineitem 
			left join supplier on s_suppkey = l_suppkey
			left join orders on l_orderkey = o_orderkey
			left join customer on o_custkey = c_custkey
			left join nation n1 on s_nationkey = n1.n_nationkey
			left join nation n2 on c_nationkey = n2.n_nationkey
		where
			(
				(n1.n_name = 'INDIA' and n2.n_name = 'MOZAMBIQUE')
				or (n1.n_name = 'MOZAMBIQUE' and n2.n_name = 'INDIA')
			)
			and cast(l_shipdate as Date) between date '1995-01-01' and date '1996-12-31'
	) as shipping
group by
	supp_nation,
	cust_nation,
	l_year
order by
	supp_nation,
	cust_nation,
	l_year 
