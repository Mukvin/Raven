-- [origin] 
create view revenue0 (supplier_no, total_revenue) as
	select
		l_suppkey,
		sum(l_extendedprice * (1 - l_discount))
	from
		lineitem
	where
		cast(l_shipdate as Date) >= date '1995-04-01'
		and cast(l_shipdate as Date) < date '1995-04-01' + interval '3' month
	group by
		l_suppkey;


select
	s_suppkey,
	s_name,
	s_address,
	s_phone,
	total_revenue
from
	supplier,
	revenue0
where
	s_suppkey = supplier_no
	and total_revenue = (
		select
			max(total_revenue)
		from
			revenue0
	)
order by
	s_suppkey;

drop view revenue0


-- [default] change join type + remove view + decorrelate manually



select
    s_suppkey,
    s_name,
    s_address,
    s_phone,
    total_revenue
from
    (
    select
        s_suppkey,
        s_name,
        s_address,
        s_phone,
        sum(l_extendedprice * (1 - l_discount)) as total_revenue
    from
        lineitem
        left join supplier on s_suppkey=l_suppkey
    where
        cast(l_shipdate as Date) >= date '1995-04-01'
					and cast(l_shipdate as Date) < date '1995-04-01' + interval '3' month
    group by s_suppkey,s_name,s_address,s_phone
)
    inner join (
    select
        max(total_revenue) as max_revenue
    from
    	(
    select
        s_suppkey,
        s_name,
        s_address,
        s_phone,
        sum(l_extendedprice * (1 - l_discount)) as total_revenue
    from
        lineitem
        left join supplier on s_suppkey=l_suppkey
    where
        cast(l_shipdate as Date) >= date '1995-04-01'
					and cast(l_shipdate as Date) < date '1995-04-01' + interval '3' month
    group by s_suppkey,s_name,s_address,s_phone
)
        
)
 on total_revenue = max_revenue
order by s_suppkey


